use anyhow::Result;
use casket::core::network::NetworkInterface;

#[cfg(feature = "cli")]
pub fn select_interface(interfaces: &[NetworkInterface]) -> Result<NetworkInterface> {
    use dialoguer::{theme::ColorfulTheme, Select};

    if interfaces.is_empty() {
        anyhow::bail!("No network interfaces found");
    }
    if interfaces.len() == 1 {
        return Ok(interfaces[0].clone());
    }

    let items: Vec<String> = interfaces.iter().map(|i| format!("{i}")).collect();
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select network interface")
        .items(&items)
        .default(0)
        .interact()?;

    Ok(interfaces[idx].clone())
}
