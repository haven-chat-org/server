/// Permission bitfield constants (Discord-style).
/// Each permission is a single bit in a u64 / i64.
pub const ADMINISTRATOR: i64         = 1 << 0;
pub const MANAGE_SERVER: i64         = 1 << 1;
pub const MANAGE_ROLES: i64          = 1 << 2;
pub const MANAGE_CHANNELS: i64       = 1 << 3;
pub const KICK_MEMBERS: i64          = 1 << 4;
pub const BAN_MEMBERS: i64           = 1 << 5;
pub const MANAGE_MESSAGES: i64       = 1 << 6;
pub const VIEW_CHANNELS: i64         = 1 << 7;
pub const SEND_MESSAGES: i64         = 1 << 8;
pub const CREATE_INVITES: i64        = 1 << 9;
pub const MANAGE_INVITES: i64        = 1 << 10;
pub const ADD_REACTIONS: i64         = 1 << 11;
pub const MENTION_EVERYONE: i64      = 1 << 12;
pub const ATTACH_FILES: i64          = 1 << 13;
pub const READ_MESSAGE_HISTORY: i64  = 1 << 14;
pub const MANAGE_EMOJIS: i64         = 1 << 15;
pub const MUTE_MEMBERS: i64         = 1 << 16;
pub const STREAM: i64               = 1 << 17;
pub const PRIORITY_SPEAKER: i64     = 1 << 18;
pub const USE_VOICE_ACTIVITY: i64   = 1 << 19;
pub const USE_EXTERNAL_EMOJIS: i64  = 1 << 20;
pub const MANAGE_WEBHOOKS: i64      = 1 << 21;
pub const VIEW_AUDIT_LOG: i64       = 1 << 22;
pub const MANAGE_EVENTS: i64        = 1 << 23;
pub const MANAGE_THREADS: i64       = 1 << 24;
pub const MODERATE_MEMBERS: i64     = 1 << 25;
pub const MANAGE_NICKNAMES: i64     = 1 << 26;

/// Default permissions for the @everyone role.
pub const DEFAULT_PERMISSIONS: i64 =
    VIEW_CHANNELS | SEND_MESSAGES | ADD_REACTIONS | READ_MESSAGE_HISTORY
    | CREATE_INVITES | ATTACH_FILES | STREAM | USE_VOICE_ACTIVITY | USE_EXTERNAL_EMOJIS;

/// Check if a permission bitfield has a specific permission.
#[inline]
pub fn has_permission(permissions: i64, required: i64) -> bool {
    // ADMINISTRATOR bypasses all checks
    if permissions & ADMINISTRATOR != 0 {
        return true;
    }
    permissions & required == required
}

/// Compute a member's effective server-level permissions.
///
/// Algorithm: start with @everyone base -> OR all member's role permissions -> ADMIN check.
/// If the user is the server owner, return all permissions.
pub fn compute_server_permissions(
    is_owner: bool,
    everyone_perms: i64,
    member_role_perms: &[i64],
) -> i64 {
    if is_owner {
        return i64::MAX; // owner has all perms
    }

    let mut perms = everyone_perms;
    for &role_perms in member_role_perms {
        perms |= role_perms;
    }

    // If ADMINISTRATOR is set, grant everything
    if perms & ADMINISTRATOR != 0 {
        return i64::MAX;
    }

    perms
}

/// Apply channel-level overwrites to a base permission set.
///
/// Process: base perms -> apply @everyone overwrite -> apply role overwrites -> apply member overwrite.
/// ADMINISTRATOR bypasses all overwrites.
pub fn apply_channel_overwrites(
    base_perms: i64,
    overwrites: &[(OverwriteTarget, i64, i64)], // (target, allow, deny)
    member_role_ids: &[uuid::Uuid],
    user_id: uuid::Uuid,
    everyone_role_id: uuid::Uuid,
) -> i64 {
    // ADMINISTRATOR bypasses
    if base_perms & ADMINISTRATOR != 0 || base_perms == i64::MAX {
        return i64::MAX;
    }

    let mut perms = base_perms;

    // 1. Apply @everyone role overwrite
    for (target, allow, deny) in overwrites {
        if let OverwriteTarget::Role(role_id) = target {
            if *role_id == everyone_role_id {
                perms &= !deny;
                perms |= allow;
            }
        }
    }

    // 2. Apply role overwrites (OR all allows, OR all denies)
    let mut role_allow: i64 = 0;
    let mut role_deny: i64 = 0;
    for (target, allow, deny) in overwrites {
        if let OverwriteTarget::Role(role_id) = target {
            if *role_id != everyone_role_id && member_role_ids.contains(role_id) {
                role_allow |= allow;
                role_deny |= deny;
            }
        }
    }
    perms &= !role_deny;
    perms |= role_allow;

    // 3. Apply member-specific overwrite
    for (target, allow, deny) in overwrites {
        if let OverwriteTarget::Member(uid) = target {
            if *uid == user_id {
                perms &= !deny;
                perms |= allow;
            }
        }
    }

    perms
}

#[derive(Debug, Clone)]
pub enum OverwriteTarget {
    Role(uuid::Uuid),
    Member(uuid::Uuid),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    // ─── has_permission ───────────────────────────────

    #[test]
    fn has_permission_single_bit_set() {
        let perms = SEND_MESSAGES;
        assert!(has_permission(perms, SEND_MESSAGES));
    }

    #[test]
    fn has_permission_single_bit_missing() {
        let perms = SEND_MESSAGES;
        assert!(!has_permission(perms, MANAGE_CHANNELS));
    }

    #[test]
    fn has_permission_administrator_bypasses_all() {
        let perms = ADMINISTRATOR;
        assert!(has_permission(perms, MANAGE_CHANNELS));
        assert!(has_permission(perms, KICK_MEMBERS));
        assert!(has_permission(perms, MANAGE_ROLES | BAN_MEMBERS));
    }

    #[test]
    fn has_permission_multiple_required_bits() {
        let perms = MANAGE_CHANNELS | MANAGE_ROLES | SEND_MESSAGES;
        assert!(has_permission(perms, MANAGE_CHANNELS | MANAGE_ROLES));
        assert!(!has_permission(perms, MANAGE_CHANNELS | KICK_MEMBERS));
    }

    #[test]
    fn has_permission_zero_perms() {
        assert!(!has_permission(0, SEND_MESSAGES));
        assert!(!has_permission(0, ADMINISTRATOR));
    }

    #[test]
    fn has_permission_default_perms() {
        assert!(has_permission(DEFAULT_PERMISSIONS, VIEW_CHANNELS));
        assert!(has_permission(DEFAULT_PERMISSIONS, SEND_MESSAGES));
        assert!(has_permission(DEFAULT_PERMISSIONS, ADD_REACTIONS));
        assert!(has_permission(DEFAULT_PERMISSIONS, CREATE_INVITES));
        assert!(!has_permission(DEFAULT_PERMISSIONS, MANAGE_CHANNELS));
        assert!(!has_permission(DEFAULT_PERMISSIONS, ADMINISTRATOR));
    }

    // ─── compute_server_permissions ───────────────────

    #[test]
    fn compute_owner_gets_all_permissions() {
        let perms = compute_server_permissions(true, 0, &[]);
        assert_eq!(perms, i64::MAX);
    }

    #[test]
    fn compute_base_everyone_perms_no_roles() {
        let perms = compute_server_permissions(false, DEFAULT_PERMISSIONS, &[]);
        assert_eq!(perms, DEFAULT_PERMISSIONS);
    }

    #[test]
    fn compute_roles_or_with_everyone() {
        let role_perms = MANAGE_CHANNELS | KICK_MEMBERS;
        let perms = compute_server_permissions(false, DEFAULT_PERMISSIONS, &[role_perms]);
        assert!(has_permission(perms, VIEW_CHANNELS)); // from @everyone
        assert!(has_permission(perms, MANAGE_CHANNELS)); // from role
        assert!(has_permission(perms, KICK_MEMBERS)); // from role
    }

    #[test]
    fn compute_multiple_roles_combined() {
        let role1 = MANAGE_CHANNELS;
        let role2 = KICK_MEMBERS;
        let perms = compute_server_permissions(false, DEFAULT_PERMISSIONS, &[role1, role2]);
        assert!(has_permission(perms, MANAGE_CHANNELS));
        assert!(has_permission(perms, KICK_MEMBERS));
        assert!(has_permission(perms, VIEW_CHANNELS)); // from @everyone
    }

    #[test]
    fn compute_admin_role_grants_all() {
        let perms = compute_server_permissions(false, DEFAULT_PERMISSIONS, &[ADMINISTRATOR]);
        assert_eq!(perms, i64::MAX);
    }

    #[test]
    fn compute_non_owner_zero_everyone_no_roles() {
        let perms = compute_server_permissions(false, 0, &[]);
        assert_eq!(perms, 0);
    }

    // ─── apply_channel_overwrites ─────────────────────

    fn make_ids() -> (Uuid, Uuid, Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn overwrite_admin_bypasses_all() {
        let (user_id, everyone_role, _, _) = make_ids();
        let base = i64::MAX; // admin/owner
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), 0, SEND_MESSAGES),
        ];
        let result = apply_channel_overwrites(base, &overwrites, &[], user_id, everyone_role);
        assert_eq!(result, i64::MAX);
    }

    #[test]
    fn overwrite_admin_bit_bypasses_all() {
        let (user_id, everyone_role, _, _) = make_ids();
        let base = ADMINISTRATOR | SEND_MESSAGES;
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), 0, SEND_MESSAGES),
        ];
        let result = apply_channel_overwrites(base, &overwrites, &[], user_id, everyone_role);
        assert_eq!(result, i64::MAX);
    }

    #[test]
    fn overwrite_everyone_deny_removes_permission() {
        let (user_id, everyone_role, _, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), 0, SEND_MESSAGES),
        ];
        let result = apply_channel_overwrites(base, &overwrites, &[], user_id, everyone_role);
        assert!(!has_permission(result, SEND_MESSAGES));
        assert!(has_permission(result, VIEW_CHANNELS)); // not denied
    }

    #[test]
    fn overwrite_everyone_allow_adds_permission() {
        let (user_id, everyone_role, _, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), MANAGE_MESSAGES, 0),
        ];
        let result = apply_channel_overwrites(base, &overwrites, &[], user_id, everyone_role);
        assert!(has_permission(result, MANAGE_MESSAGES));
    }

    #[test]
    fn overwrite_role_applied_after_everyone() {
        let (user_id, everyone_role, role_id, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        // Everyone denies SEND_MESSAGES, but role allows it back
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), 0, SEND_MESSAGES),
            (OverwriteTarget::Role(role_id), SEND_MESSAGES, 0),
        ];
        let result = apply_channel_overwrites(
            base, &overwrites, &[role_id], user_id, everyone_role,
        );
        assert!(has_permission(result, SEND_MESSAGES)); // restored by role
    }

    #[test]
    fn overwrite_role_deny_overrides_everyone_allow() {
        let (user_id, everyone_role, role_id, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        // Everyone allows MANAGE_MESSAGES, role denies it
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), MANAGE_MESSAGES, 0),
            (OverwriteTarget::Role(role_id), 0, MANAGE_MESSAGES),
        ];
        let result = apply_channel_overwrites(
            base, &overwrites, &[role_id], user_id, everyone_role,
        );
        assert!(!has_permission(result, MANAGE_MESSAGES));
    }

    #[test]
    fn overwrite_member_highest_priority() {
        let (user_id, everyone_role, role_id, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        // Everyone and role deny SEND_MESSAGES, but member overwrite allows it
        let overwrites = vec![
            (OverwriteTarget::Role(everyone_role), 0, SEND_MESSAGES),
            (OverwriteTarget::Role(role_id), 0, SEND_MESSAGES),
            (OverwriteTarget::Member(user_id), SEND_MESSAGES, 0),
        ];
        let result = apply_channel_overwrites(
            base, &overwrites, &[role_id], user_id, everyone_role,
        );
        assert!(has_permission(result, SEND_MESSAGES));
    }

    #[test]
    fn overwrite_member_deny_overrides_role_allow() {
        let (user_id, everyone_role, role_id, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        let overwrites = vec![
            (OverwriteTarget::Role(role_id), MANAGE_MESSAGES, 0),
            (OverwriteTarget::Member(user_id), 0, MANAGE_MESSAGES),
        ];
        let result = apply_channel_overwrites(
            base, &overwrites, &[role_id], user_id, everyone_role,
        );
        assert!(!has_permission(result, MANAGE_MESSAGES));
    }

    #[test]
    fn overwrite_unrelated_role_ignored() {
        let (user_id, everyone_role, _, _) = make_ids();
        let unrelated_role = Uuid::new_v4();
        let base = DEFAULT_PERMISSIONS;
        let overwrites = vec![
            (OverwriteTarget::Role(unrelated_role), MANAGE_CHANNELS, 0),
        ];
        let result = apply_channel_overwrites(base, &overwrites, &[], user_id, everyone_role);
        assert!(!has_permission(result, MANAGE_CHANNELS)); // user doesn't have the role
    }

    #[test]
    fn overwrite_no_overwrites_returns_base() {
        let (user_id, everyone_role, _, _) = make_ids();
        let base = DEFAULT_PERMISSIONS;
        let result = apply_channel_overwrites(base, &[], &[], user_id, everyone_role);
        assert_eq!(result, base);
    }
}
