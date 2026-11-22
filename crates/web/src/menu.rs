use dscan_api::auth::{CurrentUser, permissions};

/// Pozycja menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    pub label: &'static str,
    pub href: &'static str,
    pub active: bool,
}

/// (etykieta, adres, wymagane uprawnienie)
const MENU: [(&str, &str, &str); 8] = [
    ("Pulpit", "/", permissions::READ),
    ("Hosty", "/hosts", permissions::READ),
    ("Porównanie", "/compare", permissions::READ),
    ("Cele", "/targets", permissions::READ),
    ("Profile skanów", "/profiles", permissions::READ),
    ("Sygnatury", "/signatures", permissions::READ),
    ("Użytkownicy", "/users", permissions::ADMIN),
    ("Audyt", "/audit", permissions::ADMIN),
];

/// Menu dla użytkownika: tylko pozycje, do których ma uprawnienia; `active_href` jest wyróżniona.
pub fn menu_for(user: &CurrentUser, active_href: &str) -> Vec<MenuItem> {
    MENU.iter()
        .filter(|(_, _, permission)| user.has(permission))
        .map(|(label, href, _)| MenuItem {
            label,
            href,
            active: *href == active_href,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_db::SessionUser;

    fn user(permissions: &[&str]) -> CurrentUser {
        CurrentUser(SessionUser {
            id: 1,
            username: "u".into(),
            role: "r".into(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
        })
    }

    #[test]
    fn reader_does_not_see_users() {
        let labels: Vec<&str> = menu_for(&user(&["read"]), "/")
            .iter()
            .map(|item| item.label)
            .collect();
        assert_eq!(
            labels,
            vec![
                "Pulpit",
                "Hosty",
                "Porównanie",
                "Cele",
                "Profile skanów",
                "Sygnatury"
            ]
        );
    }

    #[test]
    fn admin_sees_everything() {
        assert_eq!(menu_for(&user(&["admin"]), "/").len(), 8);
    }

    #[test]
    fn active_item_is_marked() {
        let menu = menu_for(&user(&["read"]), "/targets");
        assert!(
            menu.iter()
                .any(|item| item.href == "/targets" && item.active)
        );
        assert_eq!(menu.iter().filter(|item| item.active).count(), 1);
    }
}
