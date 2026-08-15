//! Proc-macro companion for the `scadaver` ICS red team toolkit.
//!
//! # `#[derive(IntoDeviceInfo)]`
//!
//! Derives [`scadaver::core::autodetect::IntoDeviceInfo`] for a vendor device struct,
//! generating the boilerplate `HashMap` construction that converts vendor-specific fields
//! into the unified [`scadaver::core::autodetect::DeviceInfo`] type.
//!
//! ## Struct-level attribute
//!
//! `#[vendor(slug = "beckhoff")]` — the vendor slug used as `DeviceInfo::vendor`.
//!
//! ## Field-level attributes (`#[device_info(...)]`)
//!
//! | Attribute | Effect |
//! |-----------|--------|
//! | `#[device_info(ip)]` | This field becomes `DeviceInfo::ip`; not inserted into `fields` |
//! | `#[device_info(skip)]` | Field is not inserted into `fields` |
//! | `#[device_info(rename = "key")]` | Use `"key"` as the HashMap key instead of the field name |
//! | `#[device_info(optional)]` | Field is `Option<T>`; only inserted when `Some` |
//!
//! ## Example
//!
//! ```rust,ignore
//! use scadaver_macros::IntoDeviceInfo;
//!
//! #[derive(IntoDeviceInfo)]
//! #[vendor(slug = "acme")]
//! pub struct AcmeDevice {
//!     #[device_info(ip)]
//!     pub ip: String,
//!     pub firmware: String,
//!     #[device_info(rename = "hw_model")]
//!     pub hardware_model: String,
//!     #[device_info(optional)]
//!     pub serial: Option<String>,
//!     #[device_info(skip)]
//!     pub _internal_state: u8,
//! }
//! ```

use darling::{FromDeriveInput, FromField};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

// ── Darling attribute structs ─────────────────────────────────────────────────

#[derive(FromDeriveInput)]
#[darling(attributes(vendor))]
struct VendorArgs {
    slug: String,
}

#[derive(FromField)]
#[darling(attributes(device_info))]
struct FieldArgs {
    ident: Option<syn::Ident>,
    ty: Type,
    #[darling(default)]
    ip: bool,
    #[darling(default)]
    skip: bool,
    #[darling(default)]
    rename: Option<String>,
    #[darling(default)]
    optional: bool,
}

// ── Derive macro ──────────────────────────────────────────────────────────────

/// Derive [`scadaver::core::autodetect::IntoDeviceInfo`] for a vendor device struct.
///
/// Requires a `#[vendor(slug = "...")]` attribute on the struct and at least one field
/// marked `#[device_info(ip)]` that holds the device IP as a `String`.
#[proc_macro_derive(IntoDeviceInfo, attributes(vendor, device_info))]
pub fn derive_into_device_info(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_into_device_info(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_into_device_info(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;

    // Extract #[vendor(slug = "...")]
    let vendor_args = VendorArgs::from_derive_input(input)
        .map_err(|e| syn::Error::new_spanned(&input.ident, e.to_string()))?;
    let slug = &vendor_args.slug;

    // Only works on structs with named fields
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    "IntoDeviceInfo only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                struct_name,
                "IntoDeviceInfo can only be derived for structs",
            ))
        }
    };

    let mut ip_field: Option<syn::Ident> = None;
    let mut insert_stmts: Vec<TokenStream2> = Vec::new();

    for field in fields {
        let args = FieldArgs::from_field(field)
            .map_err(|e| syn::Error::new_spanned(&field.ident, e.to_string()))?;

        let ident = args
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new_spanned(&field.ident, "expected named field"))?;

        if args.ip {
            ip_field = Some(ident);
            continue;
        }
        if args.skip {
            continue;
        }

        let key = args
            .rename
            .clone()
            .unwrap_or_else(|| ident.to_string());

        if args.optional {
            // Option<T>: only insert when Some
            insert_stmts.push(quote! {
                if let Some(v) = self.#ident {
                    fields.insert(#key.to_string(), v.into());
                }
            });
        } else {
            insert_stmts.push(quote! {
                fields.insert(#key.to_string(), self.#ident.into());
            });
        }
    }

    let ip_field = ip_field.ok_or_else(|| {
        syn::Error::new_spanned(
            struct_name,
            "IntoDeviceInfo requires exactly one field marked #[device_info(ip)]",
        )
    })?;

    Ok(quote! {
        impl scadaver::core::autodetect::IntoDeviceInfo for #struct_name {
            const VENDOR_SLUG: &'static str = #slug;

            fn into_device_info(self) -> scadaver::core::autodetect::DeviceInfo {
                let mut fields = ::std::collections::HashMap::new();
                #(#insert_stmts)*
                scadaver::core::autodetect::DeviceInfo {
                    vendor: Self::VENDOR_SLUG.to_string(),
                    ip: self.#ip_field,
                    fields,
                }
            }
        }
    })
}
