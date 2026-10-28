//! Complexity measured on the parsed syntax tree, so syntax that only looks like control flow is never counted: a
//! closure's `||` is not a logical operator, and a struct literal's or a match arm's braces are not nesting
//! (FAMILY-CONTRACT section 12, search `Measures that stop counting data or syntax as logic`).
//!
//! A `match` is one decision however many arms it has, and the `?` operator adds nothing. Cognitive complexity is
//! computed on its own: control structures add one plus nesting, while early-exit guards and `else if` add one
//! without a nesting penalty. Match-arm bodies keep the match's cognitive level, and each `&&` or `||` adds one.

use syn::visit::{self, Visit};

/// The three complexity measures of one function body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SyntaxComplexity {
    /// One plus the number of decisions.
    pub(crate) cyclomatic: usize,
    /// The deepest level of nested control flow; a body with no control flow is level 0.
    pub(crate) nesting: usize,
    /// Decisions weighted by how deeply each one is nested.
    pub(crate) cognitive: usize,
}

/// Measure one function body.
pub(crate) fn syntax_complexity(block: &syn::Block) -> SyntaxComplexity {
    let mut counter = ComplexityCounter::default();
    counter.visit_block(block);
    SyntaxComplexity {
        cyclomatic: counter.decisions + 1,
        nesting: counter.max_depth,
        cognitive: counter.cognitive,
    }
}

/// Running counts while the visitor walks one body.
#[derive(Default)]
struct ComplexityCounter {
    decisions: usize,
    depth: usize,
    max_depth: usize,
    cognitive: usize,
    /// Match levels the current body sits inside, which its cognitive penalty leaves out.
    arm_levels: usize,
}

impl ComplexityCounter {
    /// Count one control structure at the current nesting level; a match arm's body pays no penalty for its match.
    fn count_structure(&mut self) {
        self.decisions += 1;
        self.cognitive += 1 + self.depth - self.arm_levels;
    }

    /// Visit a body nested one level inside the current control structure.
    fn nested<F: FnOnce(&mut Self)>(&mut self, visit_inside: F) {
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
        visit_inside(self);
        self.depth -= 1;
    }

    /// Count an `if` and the `else if` arms that follow it; an `else if` is a sibling, so it pays no nesting penalty.
    /// Returning early is the advice the cognitive rule gives, so a guard that only exits pays none either.
    fn visit_if_chain(&mut self, node: &syn::ExprIf, is_else_if: bool) {
        if is_else_if || is_early_exit_guard(node) {
            self.decisions += 1;
            self.cognitive += 1;
        } else {
            self.count_structure();
        }
        self.visit_expr(&node.cond);
        self.nested(|counter| counter.visit_block(&node.then_branch));
        if let Some((_, else_branch)) = &node.else_branch {
            match else_branch.as_ref() {
                syn::Expr::If(else_if) => self.visit_if_chain(else_if, true),
                other => self.nested(|counter| counter.visit_expr(other)),
            }
        }
    }
}

impl<'ast> Visit<'ast> for ComplexityCounter {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.visit_if_chain(node, false);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.count_structure();
        self.visit_expr(&node.expr);
        // Arms are siblings of one dispatch: the match is still a nesting level, but its arms' bodies keep its
        // cognitive level.
        self.nested(|counter| {
            counter.arm_levels += 1;
            for arm in &node.arms {
                counter.visit_arm(arm);
            }
            counter.arm_levels -= 1;
        });
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.count_structure();
        self.visit_expr(&node.expr);
        self.nested(|counter| counter.visit_block(&node.body));
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.count_structure();
        self.visit_expr(&node.cond);
        self.nested(|counter| counter.visit_block(&node.body));
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.count_structure();
        self.nested(|counter| counter.visit_block(&node.body));
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        // Only the short-circuit operators are decisions; a closure's `||` is an `ExprClosure`, never reached here.
        if matches!(node.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            self.decisions += 1;
            self.cognitive += 1;
        }
        visit::visit_expr_binary(self, node);
    }
}

/// Whether an `if` is a guard clause: no `else`, and a body of one `return`, `break`, `continue` or `panic!`.
fn is_early_exit_guard(node: &syn::ExprIf) -> bool {
    if node.else_branch.is_some() || node.then_branch.stmts.len() != 1 {
        return false;
    }
    let expr = match &node.then_branch.stmts[0] {
        syn::Stmt::Expr(expr, _) => expr,
        syn::Stmt::Macro(stmt) => return stmt.mac.path.is_ident("panic"),
        _ => return false,
    };
    match expr {
        syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_) => true,
        syn::Expr::Macro(call) => call.mac.path.is_ident("panic"),
        _ => false,
    }
}
