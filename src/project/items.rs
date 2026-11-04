use super::*;

pub(crate) struct ProjectIndexBuilders<'a> {
    pub(crate) modules: &'a mut Vec<ModuleSummary>,
    pub(crate) items: &'a mut Vec<ItemSummary>,
    pub(crate) call_names: &'a mut Vec<CallNameSummary>,
}

/// Index one parsed Rust file for project-wide analysis by recording its modules, items and call names.
///
/// `file` is the scanned file the summaries point back to, and `source` is its text, which the call-name scan reads.
/// `ast` is the parsed file whose top-level items are walked, and `module_path` is the module path they belong to.
/// `builders` holds the vectors this appends module, item and call-name summaries to; the walk starts outside any cfg or test context.
pub(crate) fn collect_project_rust_index(
    file: &SourceFile,
    source: &str,
    ast: &syn::File,
    module_path: &str,
    builders: ProjectIndexBuilders<'_>,
) {
    let scope = ProjectItemScope {
        file,
        module_path,
        cfg_context: false,
        test_context: false,
    };
    collect_project_items(scope, &ast.items, builders.modules, builders.items);
    collect_call_names(file, source, builders.call_names);
}

/// Walk the items declared in one module scope and record a summary for each kind the project index tracks.
///
/// `scope` carries the file, module path and inherited cfg and test flags, and `syn_items` are the items declared directly in that module.
/// Module summaries are appended to `modules` and all other summaries to `items`; the bodies of inline modules are walked as well.
pub(crate) fn collect_project_items(
    scope: ProjectItemScope<'_>,
    syn_items: &[Item],
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    for item in syn_items {
        collect_project_item(scope, item, modules, items);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProjectItemScope<'a> {
    pub(crate) file: &'a SourceFile,
    pub(crate) module_path: &'a str,
    pub(crate) cfg_context: bool,
    pub(crate) test_context: bool,
}

/// Send one syntax item to the collector for its kind, skipping kinds the project index does not track.
///
/// `scope` is the enclosing module context and `item` is the item to record; `use` declarations, macros and other unlisted kinds add nothing.
/// A module records itself in `modules` and its inline items through `collect_project_items`; other tracked kinds record summaries in `items`.
pub(crate) fn collect_project_item(
    scope: ProjectItemScope<'_>,
    item: &Item,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    match item {
        Item::Fn(item_fn) => collect_project_function(scope, item_fn, items),
        Item::Struct(item_struct) => collect_project_struct(scope, item_struct, items),
        Item::Enum(item_enum) => collect_project_enum(scope, item_enum, items),
        Item::Trait(item_trait) => collect_project_trait(scope, item_trait, items),
        Item::Const(item_const) => collect_project_const(scope, item_const, items),
        Item::Static(item_static) => collect_project_static(scope, item_static, items),
        Item::Type(item_type) => collect_project_type_alias(scope, item_type, items),
        Item::Impl(item_impl) => collect_project_impl(scope, item_impl, items),
        Item::Mod(item_mod) => collect_project_module(scope, item_mod, modules, items),
        _ => {}
    }
}

/// Record a free function in the project index as a `function` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_fn` is the function whose name, line, visibility and attributes fill the summary appended to `items`.
/// A test or cfg-test attribute marks it as test code, and an export attribute or `is_reached_without_rust_reference` sets its exported flag.
pub(crate) fn collect_project_function(
    scope: ProjectItemScope<'_>,
    item_fn: &syn::ItemFn,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_fn.sig.ident.to_string(),
        "function",
        line_from_span(item_fn.sig.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_fn.vis),
            externally_public: visibility_is_externally_public(&item_fn.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_fn.attrs),
            test_context: scope.test_context
                || has_test_attr(&item_fn.attrs)
                || has_cfg_test_attr(&item_fn.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_fn.attrs)
                || is_reached_without_rust_reference(&item_fn.attrs, &item_fn.sig, &item_fn.block),
        },
    ));
}

/// Record a struct in the project index as a `struct` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_struct` is the struct whose name, line, visibility and attributes fill the summary appended to `items`.
/// Only a test scope or a cfg-test attribute marks it as test code, and only an export attribute sets its exported flag.
pub(crate) fn collect_project_struct(
    scope: ProjectItemScope<'_>,
    item_struct: &syn::ItemStruct,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_struct.ident.to_string(),
        "struct",
        line_from_span(item_struct.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_struct.vis),
            externally_public: visibility_is_externally_public(&item_struct.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_struct.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_struct.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_struct.attrs),
        },
    ));
}

/// Record an enum in the project index as an `enum` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_enum` is the enum whose name, line, visibility and attributes fill the summary appended to `items`.
/// Only a test scope or a cfg-test attribute marks it as test code, and only an export attribute sets its exported flag.
pub(crate) fn collect_project_enum(
    scope: ProjectItemScope<'_>,
    item_enum: &syn::ItemEnum,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_enum.ident.to_string(),
        "enum",
        line_from_span(item_enum.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_enum.vis),
            externally_public: visibility_is_externally_public(&item_enum.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_enum.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_enum.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_enum.attrs),
        },
    ));
}

/// Record a trait in the project index as a `trait` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_trait` is the trait whose name, line, visibility and attributes fill the summary appended to `items`.
/// Only a test scope or a cfg-test attribute marks it as test code, and only an export attribute sets its exported flag.
pub(crate) fn collect_project_trait(
    scope: ProjectItemScope<'_>,
    item_trait: &syn::ItemTrait,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_trait.ident.to_string(),
        "trait",
        line_from_span(item_trait.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_trait.vis),
            externally_public: visibility_is_externally_public(&item_trait.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_trait.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_trait.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_trait.attrs),
        },
    ));
}

/// Record a constant in the project index as a `const` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_const` is the constant whose name, line, visibility and attributes fill the summary appended to `items`.
/// Only a test scope or a cfg-test attribute marks it as test code, and only an export attribute sets its exported flag.
pub(crate) fn collect_project_const(
    scope: ProjectItemScope<'_>,
    item_const: &syn::ItemConst,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_const.ident.to_string(),
        "const",
        line_from_span(item_const.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_const.vis),
            externally_public: visibility_is_externally_public(&item_const.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_const.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_const.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_const.attrs),
        },
    ));
}

/// Record a static in the project index as a `static` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_static` is the static whose name, line, visibility and attributes fill the summary appended to `items`.
/// Only a test scope or a cfg-test attribute marks it as test code, and only an export attribute sets its exported flag.
pub(crate) fn collect_project_static(
    scope: ProjectItemScope<'_>,
    item_static: &syn::ItemStatic,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_static.ident.to_string(),
        "static",
        line_from_span(item_static.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_static.vis),
            externally_public: visibility_is_externally_public(&item_static.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_static.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_static.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_static.attrs),
        },
    ));
}

/// Record a type alias in the project index as a `type alias` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags.
/// `item_type` is the alias whose name, line, visibility and attributes fill the summary appended to `items`.
/// Only a test scope or a cfg-test attribute marks it as test code, and only an export attribute sets its exported flag.
pub(crate) fn collect_project_type_alias(
    scope: ProjectItemScope<'_>,
    item_type: &syn::ItemType,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_type.ident.to_string(),
        "type alias",
        line_from_span(item_type.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_type.vis),
            externally_public: visibility_is_externally_public(&item_type.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_type.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_type.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_type.attrs),
        },
    ));
}

/// Record every method of an impl block in the project index, skipping associated constants, types and macros.
///
/// `scope` is the enclosing module context and `item_impl` is the impl block whose `fn` items are walked.
/// Each method summary is appended to `items` by `collect_project_method`.
pub(crate) fn collect_project_impl(
    scope: ProjectItemScope<'_>,
    item_impl: &syn::ItemImpl,
    items: &mut Vec<ItemSummary>,
) {
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            collect_project_method(scope, item_impl, method, items);
        }
    }
}

/// Record one method of an impl block in the project index as a `method` item.
///
/// `scope` gives the file, module path and inherited cfg and test flags, and `item_impl` is the enclosing impl block.
/// `method` is the method whose summary is appended to `items`; cfg or test attributes on the block or the method set its matching flags.
/// Its container is the impl's self type name, a trait impl sets its trait flag, and export detection matches `collect_project_function`.
pub(crate) fn collect_project_method(
    scope: ProjectItemScope<'_>,
    item_impl: &syn::ItemImpl,
    method: &syn::ImplItemFn,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        method.sig.ident.to_string(),
        "method",
        line_from_span(method.sig.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&method.vis),
            externally_public: visibility_is_externally_public(&method.vis),
            cfg_gated: scope.cfg_context
                || has_cfg_attr(&item_impl.attrs)
                || has_cfg_attr(&method.attrs),
            test_context: scope.test_context
                || has_test_attr(&item_impl.attrs)
                || has_cfg_test_attr(&item_impl.attrs)
                || has_test_attr(&method.attrs)
                || has_cfg_test_attr(&method.attrs),
            container: impl_self_type_name(item_impl),
            trait_impl: item_impl.trait_.is_some(),
            exported_by_attr: has_export_attr(&method.attrs)
                || is_reached_without_rust_reference(&method.attrs, &method.sig, &method.block),
        },
    ));
}

/// Record a module declaration in the project index and walk the items of an inline module body under the module's own scope.
///
/// `scope` is the parent module context, and `item_mod` is the `mod` item whose summary is appended to `modules`.
/// An inline body's items go to `modules` and `items` under the joined module path, inheriting the module's cfg gating and test context.
pub(crate) fn collect_project_module(
    scope: ProjectItemScope<'_>,
    item_mod: &syn::ItemMod,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    let current_module = module_name(scope.module_path, &item_mod.ident.to_string());
    let module_cfg_gated = scope.cfg_context || has_cfg_attr(&item_mod.attrs);
    let module_test_context = scope.test_context || is_test_module(item_mod);
    modules.push(ModuleSummary {
        file_path: scope.file.display_path.clone(),
        module_path: current_module.clone(),
        line: line_from_span(item_mod.ident.span().start()),
        public: visibility_is_public(&item_mod.vis),
        inline: item_mod.content.is_some(),
        cfg_gated: module_cfg_gated,
    });
    if let Some((_, nested)) = &item_mod.content {
        let nested_scope = ProjectItemScope {
            file: scope.file,
            module_path: &current_module,
            cfg_context: module_cfg_gated,
            test_context: module_test_context,
        };
        collect_project_items(nested_scope, nested, modules, items);
    }
}

/// Build the item summary the project index stores for one declaration.
///
/// `scope` supplies the file display path and module path, `name` is the declared identifier, and `kind` is the item kind label such as `method`.
/// `line` is the declared name's line, and `context` holds the container name and the visibility, cfg, test, trait-impl and export flags.
/// Returns the `ItemSummary` holding those values, with `kind` copied into an owned string.
pub(crate) fn project_item(
    scope: ProjectItemScope<'_>,
    name: String,
    kind: &str,
    line: usize,
    context: ProjectItemContext,
) -> ItemSummary {
    ItemSummary {
        file_path: scope.file.display_path.clone(),
        module_path: scope.module_path.to_string(),
        name,
        kind: kind.to_string(),
        container: context.container,
        line,
        public: context.public,
        externally_public: context.externally_public,
        cfg_gated: context.cfg_gated,
        test_context: context.test_context,
        trait_impl: context.trait_impl,
        exported_by_attr: context.exported_by_attr,
    }
}

/// Tell whether an item carries an attribute that exports it by symbol name or to Python, such as `no_mangle` or `pyfunction`.
///
/// `attrs` are the item's attributes, each matched on the last segment of its path by `attr_ident_is_export`.
/// A Rust 2024 `unsafe(...)` wrapper also counts when its inner tokens contain `no_mangle` or `export_name` as text.
/// Returns true when any attribute matches and false otherwise, including for an empty slice.
pub(crate) fn has_export_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let Some(segment) = attr.path().segments.last() else {
            return false;
        };
        if attr_ident_is_export(&segment.ident) {
            return true;
        }
        // Rust 2024 wraps these as `#[unsafe(no_mangle)]` / `#[unsafe(export_name = ...)]`,
        // so the attribute path is `unsafe` and the export ident sits in the inner tokens.
        if segment.ident == "unsafe" {
            if let syn::Meta::List(list) = &attr.meta {
                let inner = list.tokens.to_string();
                return inner.contains("no_mangle") || inner.contains("export_name");
            }
        }
        false
    })
}

/// Match an attribute name against the export markers `no_mangle`, `export_name`, `pymodule` and `pyfunction`.
///
/// `ident` is the last segment of an attribute path, as `has_export_attr` passes it.
/// Returns true only for one of those four names.
fn attr_ident_is_export(ident: &syn::Ident) -> bool {
    ident == "no_mangle" || ident == "export_name" || ident == "pymodule" || ident == "pyfunction"
}

/// Name the type an impl block is written for, so its method summaries can record a container.
///
/// `item_impl` is the impl block whose self type is read.
/// Returns the last segment of a path self type, such as `Config` for `crate::Config`, or None for a reference, tuple or other non-path type.
fn impl_self_type_name(item_impl: &syn::ItemImpl) -> Option<String> {
    let syn::Type::Path(path) = item_impl.self_ty.as_ref() else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// Join a child module name onto its parent module path with `::`.
///
/// `parent` is the enclosing module path, which may be empty, and `name` is the child module's identifier.
/// Returns `name` alone when `parent` is empty, otherwise the two joined by `::`.
pub(crate) fn module_name(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}::{name}")
    }
}

/// Derive a source file's module path from its display path under `src/`.
///
/// `file` is the scanned source file whose display path is read.
/// Returns the path with `/` turned into `::` after dropping `src/` and a trailing `/mod.rs` or `.rs`, so `src/a/b.rs` gives `a::b`.
/// Returns an empty string for `src/lib.rs`, `src/main.rs` and any display path that does not start with `src/`.
pub(crate) fn inferred_file_module_path(file: &SourceFile) -> String {
    let Some(path) = file.display_path.strip_prefix("src/") else {
        return String::new();
    };
    if matches!(path, "lib.rs" | "main.rs") {
        return String::new();
    }

    let without_extension = path
        .strip_suffix("/mod.rs")
        .or_else(|| path.strip_suffix(".rs"))
        .unwrap_or(path);
    without_extension.replace('/', "::")
}
