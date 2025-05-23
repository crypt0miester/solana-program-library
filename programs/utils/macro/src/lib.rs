use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_quote, spanned::Spanned};
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, ExprPath, Fields, GenericArgument, Ident, PathArguments, Type, TypePath
};
extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

/// Attach like:
/// #[derive(PAccount)]
/// #[program_id = "crate::ID"]  // optional, defaults to crate::ID
#[proc_macro_derive(PAccount, attributes(program_id))]
pub fn derive_paccount(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // pull the #[program_id = "..."] attribute, defaulting to crate::ID
    let mut prog: Option<ExprPath> = None;
    for attr in &input.attrs {
        if attr.path.is_ident("program_id") {
            prog = Some(attr.parse_args().expect("`program_id` must be a path"));
        }
    }
    let prog = prog.unwrap_or_else(|| parse_quote! { crate::ID });

    let expanded = quote! {
        impl #name {
            #[inline]
            pub fn from_account_info(account_info: &AccountInfo)
                -> Result<Ref<Self>, ProgramError>
            {
                if !account_info.is_owned_by(&#prog) {
                    return Err(ProgramError::InvalidAccountOwner);
                }
                let data = account_info.try_borrow_data()?;
                if data.len() < Self::LEN {
                    return Err(ProgramError::InvalidAccountData);
                }
                Ok(Ref::map(data, |d| unsafe {
                    Self::from_bytes_unchecked(d)
                }))
            }

            #[inline]
            pub unsafe fn from_account_info_unchecked(
                account_info: &AccountInfo,
            ) -> Result<&Self, ProgramError> {
                if account_info.owner() != &#prog {
                    return Err(ProgramError::InvalidAccountOwner);
                }
                let data = account_info.borrow_data_unchecked();
                if data.len() < Self::LEN {
                    return Err(ProgramError::InvalidAccountData);
                }
                Ok(Self::from_bytes_unchecked(data))
            }

            #[inline(always)]
            pub fn from_bytes(bytes: &[u8])
                -> Result<&Self, ProgramError>
            {
                if bytes.len() < Self::LEN {
                    return Err(ProgramError::InvalidArgument);
                }
                Ok(unsafe { Self::from_bytes_unchecked(bytes) })
            }

            #[inline(always)]
            pub unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
                &*(bytes.as_ptr() as *const Self)
            }

            #[inline(always)]
            pub fn from_bytes_mut(bytes: &mut [u8])
                -> Result<&mut Self, ProgramError>
            {
                if bytes.len() < Self::LEN {
                    return Err(ProgramError::InvalidArgument);
                }
                Ok(unsafe { Self::from_bytes_mut_unchecked(bytes) })
            }

            #[inline(always)]
            pub unsafe fn from_bytes_mut_unchecked(bytes: &mut [u8]) -> &mut Self {
                &mut *(bytes.as_mut_ptr() as *mut Self)
            }
        }
    };

    expanded.into()
}

/// Derive helper for plain-data structs: adds `LEN` and `load_unchecked`.
#[proc_macro_derive(PStruct)]
pub fn derive_pstruct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl #name {
            /// Total byte length of this struct
            pub const LEN: usize = core::mem::size_of::<Self>();

            /// # Safety
            ///
            /// Caller must validate `bytes.len() >= LEN` before calling.
            #[inline(always)]
            pub(crate) unsafe fn load_unchecked(bytes: &[u8]) -> &Self {
                &*(bytes.as_ptr() as *const Self)
            }
        }
    };

    expanded.into()
}

/// Derives `From<u8>` for an enum by mapping each byte to the corresponding enum variant.
/// Panics if the value is outside the defined variants.
#[proc_macro_derive(FromEnum)]
pub fn derive_from_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let variants = match input.data {
        Data::Enum(e) => e.variants.into_iter().map(|v| v.ident),
        _ => panic!("#[derive(FromEnum)] only works on enums"),
    };
    let arms = variants.clone().enumerate().map(|(_i, var)| {
        quote! { x if x == #name::#var as u8 => #name::#var }
    });
    let expanded = quote! {
        impl From<u8> for #name {
            fn from(x: u8) -> Self {
                match x {
                    #(#arms, )*
                    _ => panic!("invalid {} value: {}", stringify!(#name), x),
                }
            }
        }
    };
    expanded.into()
}

/// Derives `From<Enum> for u8` by mapping each enum variant to its index as a `u8`.
#[proc_macro_derive(FromU8)]
pub fn derive_from_u8(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let variants = match input.data {
        Data::Enum(e) => e.variants.into_iter().map(|v| v.ident).collect::<Vec<_>>(),
        _ => panic!("#[derive(FromU8)] only works on enums"),
    };
    let arms = variants.iter().enumerate().map(|(i, var)| {
        quote! { #name::#var => #i as u8 }
    });
    let expanded = quote! {
        impl From<#name> for u8 {
            fn from(x: #name) -> Self {
                match x {
                    #(#arms, )*
                }
            }
        }
    };
    expanded.into()
}

/// Derive `TryFrom<&[u8]>` for instruction enums, parsing fields from byte slices.
///
/// This macro generates an implementation of `TryFrom<&[u8]>` for an enum, enabling
/// it to parse instruction data from a byte slice. The enum uses a `u8` discriminant
/// (max 256 variants). Each variant’s fields are parsed sequentially based on their types.
///
/// ### Supported Field Types
/// - `String`: u32 length (little-endian) followed by UTF-8 bytes.
/// - `Pubkey`: 32-byte public key.
/// - `u64`, `u32`, `u16`, `u8`: Unsigned integers in little-endian format.
/// - `bool`: Single byte (0 = false, non-zero = true).
/// - `Option<T>`: Single byte (0 = None, 1 = Some) followed by `T` if Some.
/// - `Vec<T>`: u32 length (little-endian) followed by `T` elements.
/// - Custom types: Must define `LEN: usize` and implement `TryFrom<&[u8]>`.
///
/// ### Panics
/// - If the enum exceeds 256 variants (due to `u8` discriminant).
/// - If a field type is unsupported, with a message specifying the unsupported type (e.g., `'f32'`).
#[proc_macro_derive(PInstruction)]
pub fn derive_pinstruction(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let input_data = input.data.clone();
    let enum_data = match input_data {
        Data::Enum(e) => e,
        _ => panic!("#[derive(PInstruction)] only works on enums"),
    };

    // Ensure variant count fits within u8 (256 max)
    if enum_data.variants.len() > 256 {
        panic!("#[derive(PInstruction)] exceeds 256 variant limit due to u8 discriminant");
    }

    // Generate parsing logic for each variant
    let arms = enum_data.variants.iter().enumerate().map(|(i, v)| {
        let var_ident = &v.ident;
        let disc = i as u8;
        match &v.fields {
            Fields::Unit => quote! { #disc => Ok(#name::#var_ident) },
            Fields::Named(flds) => {
                let mut stmts = Vec::new();
                let mut binds = Vec::new();
                for field in &flds.named {
                    let fident = field.ident.as_ref().unwrap();
                    let stmt = generate_field_parser(&field.ty, fident, &input.attrs);
                    stmts.push(stmt);
                    binds.push(quote! { #fident });
                }
                quote! {
                    #disc => {
                        let mut rem = rem;
                        #(#stmts)*
                        Ok(#name::#var_ident { #(#binds),* })
                    }
                }
            },
            Fields::Unnamed(flds) => {
                let mut stmts = Vec::new();
                let mut binds = Vec::new();
                for (idx, field) in flds.unnamed.iter().enumerate() {
                    let fident = Ident::new(&format!("field_{}", idx), field.span());
                    let stmt = generate_field_parser(&field.ty, &fident, &input.attrs);                    
                    stmts.push(stmt);
                    binds.push(quote! { #fident });
                }
                quote! {
                    #disc => {
                        let mut rem = rem;
                        #(#stmts)*
                        Ok(#name::#var_ident(#(#binds),*))
                    }
                }
            },
        }
    });

    // Generate the TryFrom implementation
    let expanded = quote! {
        impl ::core::convert::TryFrom<&[u8]> for #name {
            type Error = ProgramError;
            fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
                if input.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let (&tag, rem) = input.split_first().ok_or(ProgramError::InvalidInstructionData)?;
                match tag {
                    #(#arms),*,
                    _ => Err(ProgramError::InvalidInstructionData),
                }
            }
        }
    };
    TokenStream::from(expanded)
}

/// Generates parsing logic for a field based on its type.
///
/// This internal function creates code to parse a single field from the byte slice `rem`,
/// advancing `rem` past the parsed data. The generated code assumes `invalid_data` is
/// in scope for error handling.
///
/// ### Panics
/// - If the type is unsupported, with a message including the specific type (e.g., `'f32'`).
fn generate_parser(ty: &Type, attrs: &[Attribute]) -> TokenStream2 {
    if let Type::Path(path) = ty {
        let seg = path.path.segments.last().unwrap();
        let type_name = seg.ident.to_string();
        match type_name.as_str() {
            "String" => quote! {
                // Parse a length-prefixed string: u32 length + UTF-8 bytes
                {
                    if rem.len() < 4 { return Err(ProgramError::InvalidInstructionData); }
                    let len = u32::from_le_bytes(rem[0..4].try_into().map_err(|_| ProgramError::InvalidInstructionData)?) as usize;
                    rem = &rem[4..];
                    if rem.len() < len { return Err(ProgramError::InvalidInstructionData); }
                    let value = String::from_utf8(rem[0..len].to_vec()).map_err(|_| ProgramError::InvalidInstructionData)?;
                    rem = &rem[len..];
                    value
                }
            },
            "Pubkey" => quote! {
                // Parse a 32-byte Pubkey
                {
                    if rem.len() < 32 { return Err(ProgramError::InvalidInstructionData); }
                    let value: Pubkey = rem[0..32].try_into().map_err(|_| ProgramError::InvalidInstructionData)?;
                    rem = &rem[32..];
                    value
                }
            },
            "u64" => quote! {
                // Parse a little-endian u64 (8 bytes)
                {
                    if rem.len() < 8 { return Err(ProgramError::InvalidInstructionData); }
                    let value = u64::from_le_bytes(rem[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
                    rem = &rem[8..];
                    value
                }
            },
            "u32" => quote! {
                // Parse a little-endian u32 (4 bytes)
                {
                    if rem.len() < 4 { return Err(ProgramError::InvalidInstructionData); }
                    let value = u32::from_le_bytes(rem[0..4].try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
                    rem = &rem[4..];
                    value
                }
            },
            "u16" => quote! {
                // Parse a little-endian u16 (2 bytes)
                {
                    if rem.len() < 2 { return Err(ProgramError::InvalidInstructionData); }
                    let value = u16::from_le_bytes(rem[0..2].try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
                    rem = &rem[2..];
                    value
                }
            },
            "u8" => quote! {
                // Parse a single u8 byte
                {
                    if rem.is_empty() { return Err(ProgramError::InvalidInstructionData); }
                    let value = rem[0];
                    rem = &rem[1..];
                    value
                }
            },
            "bool" => quote! {
                // Parse a bool: 0 = false, non-zero = true
                {
                    if rem.is_empty() { return Err(ProgramError::InvalidInstructionData); }
                    let value = rem[0] != 0;
                    rem = &rem[1..];
                    value
                }
            },
            "Option" => {
                if let PathArguments::AngleBracketed(gen) = &seg.arguments {
                    if let Some(GenericArgument::Type(inner_ty)) = gen.args.first() {
                        let inner_parser = generate_parser(inner_ty, attrs);
                        quote! {
                            // Parse an Option: 1 byte (0 = None, 1 = Some) + inner type if Some
                            {
                                if rem.is_empty() { return Err(ProgramError::InvalidInstructionData); }
                                let is_some = rem[0] != 0;
                                rem = &rem[1..];
                                let value = if is_some {
                                    Some(#inner_parser)
                                } else {
                                    None
                                };
                                value
                            }
                        }
                    } else {
                        panic!("#[derive(PInstruction)] Option<T> must have a concrete type");
                    }
                } else {
                    panic!("#[derive(PInstruction)] Option must have generics");
                }
            },
            "Vec" => {
                if let PathArguments::AngleBracketed(gen) = &seg.arguments {
                    if let Some(GenericArgument::Type(inner_ty)) = gen.args.first() {
                        let elem_parser = generate_parser(inner_ty, attrs);
                        if check_is_enum(inner_ty) {
                            quote! {
                                // Parse a Vec of simple enums: u32 length + u8 elements
                                {
                                    if rem.len() < 4 { return Err(ProgramError::InvalidInstructionData); }
                                    let count = u32::from_le_bytes(rem[0..4].try_into().map_err(|_| ProgramError::InvalidInstructionData)?) as usize;
                                    rem = &rem[4..];
                                    if rem.len() < count { return Err(ProgramError::InvalidInstructionData); }
                                    let mut vec = Vec::with_capacity(count);
                                    for _ in 0..count {
                                        vec.push(#elem_parser);
                                    }
                                    vec
                                }
                            }
                        } else {
                            quote! {
                                // Parse a Vec<T>: u32 length + repeated T elements
                                {
                                    if rem.len() < 4 { return Err(ProgramError::InvalidInstructionData); }
                                    let count = u32::from_le_bytes(rem[0..4].try_into().map_err(|_| ProgramError::InvalidInstructionData)?) as usize;
                                    rem = &rem[4..];
                                    let mut vec = Vec::with_capacity(count);
                                    for _ in 0..count {
                                        vec.push(#elem_parser);
                                    }
                                    vec
                                }
                            }
                        }
                    } else {
                        panic!("#[derive(PInstruction)] Vec<T> must have a concrete type");
                    }
                } else {
                    panic!("#[derive(PInstruction)] Vec must have generics");
                }
            },
            _ => {
                let type_path = &path.path;
                if check_is_enum(ty) {
                    quote! {
                        // Parse a simple enum with From<u8>
                        {
                            if rem.is_empty() { return Err(ProgramError::InvalidInstructionData); }
                            let value = #type_path::from(rem[0]);
                            rem = &rem[1..];
                            value
                        }
                    }
                } else {
                    // Assume struct with PStruct (LEN and load_unchecked)
                    quote! {
                        // Parse a struct with LEN and load_unchecked
                        {
                            if rem.len() < #type_path::LEN { return Err(ProgramError::InvalidInstructionData); }
                            let value = unsafe { #type_path::load_unchecked(rem) }.clone();
                            rem = &rem[#type_path::LEN..];
                            value
                        }
                    }
                }
            },
        }
    } else {
        let ty_str = quote::quote!(#ty).to_string();
        panic!(
            "#[derive(PInstruction)] encountered an unsupported field type: '{}'. Only path types (e.g., String, u32, Vec<T>) are supported.",
            ty_str
        );
    }
}

/// Generates parsing logic for a field based on its type.
///
/// This internal function creates code to parse a single field from the byte slice `rem`,
/// advancing `rem` past the parsed data. The generated code assumes `invalid_data` is
/// in scope for error handling.
///
/// ### Parameters
/// - `ty`: The type of the field.
/// - `field_ident`: The identifier to bind the parsed value to.
/// - `attrs`: Attributes from the parent enum to check for simple enums.
///
/// ### Panics
/// - If the type is unsupported, with a message including the specific type (e.g., `'f32'`).
fn generate_field_parser(ty: &Type, field_ident: &Ident, attrs: &[Attribute]) -> TokenStream2 {
    let parser = generate_parser(ty, attrs);
    quote! {
        let #field_ident = #parser;
    }
}

// fn check_is_enum(ty: &Type) -> bool {
//     if let Type::Path(path) = ty {
//         // Check if the last path segment has IsEnum in its generics or where clauses
//         // This is a heuristic - it works for types marked with #[derive(IsEnum)]
//         // because the derived trait is included in the type info
//         let path_str = quote::quote!(#path).to_string();
//         if path_str.contains("IsEnum") || path_str.contains("::is_enum") {
//             return true;
//         }
        
//         // Check if the type has FromEnum or FromU8 derivations, which are common for enums
//         if path_str.contains("FromEnum") || path_str.contains("FromU8") {
//             return true;
//         }
//     }
    
//     false
// }

fn check_is_enum(ty: &Type) -> bool {
    if let Type::Path(path) = ty {
        // Extract type information as string for pattern analysis
        let ty_str = quote::quote!(#ty).to_string();
        
        // Check for enum-specific attributes and patterns
        
        // 1. Check for #[repr(u8)] which is common for simple enums
        if ty_str.contains("repr") && ty_str.contains("u8") {
            return true;
        }
        
        // 2. Check for enum-specific derive macros
        if ty_str.contains("FromEnum") || 
           ty_str.contains("FromU8") || 
           ty_str.contains("IsEnum") {
            return true;
        }
        
        // 3. Check for TryFrom<&[u8]> or From<u8> implementations 
        // which are typically on enums
        if ty_str.contains("TryFrom") || 
           (ty_str.contains("From") && ty_str.contains("<u8>")) {
            return true;
        }
    }
    
    false
}

// Add this somewhere in your macro crate's public API
#[proc_macro]
pub fn define_is_enum_trait(_input: TokenStream) -> TokenStream {
    quote! {
        /// Marker trait for simple enums (enums that can be parsed from a single byte)
        pub trait IsEnum {
            /// Returns true if the type is a simple enum
            fn is_enum() -> bool {
                true
            }
        }
    }.into()
}

#[proc_macro_derive(IsEnum)]
pub fn derive_simple_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    
    // Verify that this is actually an enum
    match input.data {
        Data::Enum(_) => {}, // good
        _ => panic!("#[derive(IsEnum)] only works on enums"),
    };
    
    let expanded = quote! {
        impl IsEnum for #name {}
    };
    
    TokenStream::from(expanded)
}