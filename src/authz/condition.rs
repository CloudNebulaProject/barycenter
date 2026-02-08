//! Simple expression parser and evaluator for ABAC policy conditions.
//!
//! Supported syntax:
//! - Comparisons: `==`, `!=`, `>`, `<`, `>=`, `<=`
//! - Boolean operators: `&&`, `||`, `!`
//! - Membership: `x in list`
//! - Dot-path access: `request.ip`, `context.corporate_ips`
//! - Literals: integers, floats, `"strings"`, `true`, `false`
//! - Parentheses for grouping

use crate::authz::errors::AuthzError;
use serde_json::Value;

// ─── AST ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(LitValue),
    Path(Vec<String>),
    BinOp {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    UnaryNot(Box<Expr>),
    In {
        element: Box<Expr>,
        collection: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LitValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
}

// ─── Parser ─────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    True,
    False,
    Dot,
    LParen,
    RParen,
    Eq,  // ==
    Ne,  // !=
    Gt,  // >
    Lt,  // <
    Ge,  // >=
    Le,  // <=
    And, // &&
    Or,  // ||
    Not, // !
    In,  // in
}

fn tokenize(input: &str) -> Result<Vec<Token>, AuthzError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '=' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::Eq);
                i += 2;
            }
            '!' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::Ne);
                i += 2;
            }
            '!' => {
                tokens.push(Token::Not);
                i += 1;
            }
            '>' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::Ge);
                i += 2;
            }
            '>' => {
                tokens.push(Token::Gt);
                i += 1;
            }
            '<' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                tokens.push(Token::Le);
                i += 2;
            }
            '<' => {
                tokens.push(Token::Lt);
                i += 1;
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                tokens.push(Token::And);
                i += 2;
            }
            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                tokens.push(Token::Or);
                i += 2;
            }
            '"' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(AuthzError::InvalidCondition(
                        "unterminated string literal".into(),
                    ));
                }
                let s: String = chars[start..i].iter().collect();
                tokens.push(Token::Str(s));
                i += 1; // skip closing quote
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let num_str: String = chars[start..i].iter().collect();
                if num_str.contains('.') {
                    let f: f64 = num_str.parse().map_err(|_| {
                        AuthzError::InvalidCondition(format!("invalid float `{num_str}`"))
                    })?;
                    tokens.push(Token::Float(f));
                } else {
                    let n: i64 = num_str.parse().map_err(|_| {
                        AuthzError::InvalidCondition(format!("invalid integer `{num_str}`"))
                    })?;
                    tokens.push(Token::Int(n));
                }
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.as_str() {
                    "true" => tokens.push(Token::True),
                    "false" => tokens.push(Token::False),
                    "in" => tokens.push(Token::In),
                    _ => tokens.push(Token::Ident(word)),
                }
            }
            c => {
                return Err(AuthzError::InvalidCondition(format!(
                    "unexpected character `{c}`"
                )));
            }
        }
    }
    Ok(tokens)
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        tok
    }

    fn expect_rparen(&mut self) -> Result<(), AuthzError> {
        if self.advance() != Some(Token::RParen) {
            return Err(AuthzError::InvalidCondition(
                "expected closing parenthesis `)`".into(),
            ));
        }
        Ok(())
    }

    /// Entry: parse_or
    fn parse_expr(&mut self) -> Result<Expr, AuthzError> {
        self.parse_or()
    }

    /// or_expr = and_expr ("||" and_expr)*
    fn parse_or(&mut self) -> Result<Expr, AuthzError> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::BinOp {
                op: BinOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// and_expr = comparison ("&&" comparison)*
    fn parse_and(&mut self) -> Result<Expr, AuthzError> {
        let mut left = self.parse_comparison()?;
        while self.peek() == Some(&Token::And) {
            self.advance();
            let right = self.parse_comparison()?;
            left = Expr::BinOp {
                op: BinOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    /// comparison = unary (("==" | "!=" | ">" | "<" | ">=" | "<=" | "in") unary)?
    fn parse_comparison(&mut self) -> Result<Expr, AuthzError> {
        let left = self.parse_unary()?;
        match self.peek() {
            Some(Token::Eq) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::BinOp {
                    op: BinOp::Eq,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Some(Token::Ne) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::BinOp {
                    op: BinOp::Ne,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Some(Token::Gt) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::BinOp {
                    op: BinOp::Gt,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Some(Token::Lt) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::BinOp {
                    op: BinOp::Lt,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Some(Token::Ge) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::BinOp {
                    op: BinOp::Ge,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Some(Token::Le) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::BinOp {
                    op: BinOp::Le,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Some(Token::In) => {
                self.advance();
                let right = self.parse_unary()?;
                Ok(Expr::In {
                    element: Box::new(left),
                    collection: Box::new(right),
                })
            }
            _ => Ok(left),
        }
    }

    /// unary = "!" unary | primary
    fn parse_unary(&mut self) -> Result<Expr, AuthzError> {
        if self.peek() == Some(&Token::Not) {
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::UnaryNot(Box::new(expr)));
        }
        self.parse_primary()
    }

    /// primary = literal | path | "(" expr ")"
    fn parse_primary(&mut self) -> Result<Expr, AuthzError> {
        match self.peek().cloned() {
            Some(Token::Int(n)) => {
                self.advance();
                Ok(Expr::Literal(LitValue::Int(n)))
            }
            Some(Token::Float(f)) => {
                self.advance();
                Ok(Expr::Literal(LitValue::Float(f)))
            }
            Some(Token::Str(s)) => {
                self.advance();
                Ok(Expr::Literal(LitValue::Str(s)))
            }
            Some(Token::True) => {
                self.advance();
                Ok(Expr::Literal(LitValue::Bool(true)))
            }
            Some(Token::False) => {
                self.advance();
                Ok(Expr::Literal(LitValue::Bool(false)))
            }
            Some(Token::Ident(name)) => {
                self.advance();
                let mut path = vec![name];
                while self.peek() == Some(&Token::Dot) {
                    self.advance();
                    match self.advance() {
                        Some(Token::Ident(seg)) => path.push(seg),
                        _ => {
                            return Err(AuthzError::InvalidCondition(
                                "expected identifier after `.`".into(),
                            ));
                        }
                    }
                }
                Ok(Expr::Path(path))
            }
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_rparen()?;
                Ok(expr)
            }
            other => Err(AuthzError::InvalidCondition(format!(
                "unexpected token: {other:?}"
            ))),
        }
    }
}

/// Parse a condition expression string into an AST.
pub fn parse_condition(input: &str) -> Result<Expr, AuthzError> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(AuthzError::InvalidCondition("empty expression".into()));
    }
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    if parser.pos < parser.tokens.len() {
        return Err(AuthzError::InvalidCondition(format!(
            "unexpected trailing token: {:?}",
            parser.tokens[parser.pos]
        )));
    }
    Ok(expr)
}

// ─── Evaluator ──────────────────────────────────────────────────────────

/// Evaluate a parsed expression against a JSON context.
/// Returns `true` if the condition is satisfied.
pub fn evaluate(expr: &Expr, context: &Value) -> Result<bool, AuthzError> {
    match eval_value(expr, context)? {
        EvalResult::Bool(b) => Ok(b),
        other => Err(AuthzError::InvalidCondition(format!(
            "condition must evaluate to boolean, got: {other:?}"
        ))),
    }
}

#[derive(Debug, Clone)]
enum EvalResult {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Array(Vec<EvalResult>),
    Null,
}

impl EvalResult {
    fn as_f64(&self) -> Option<f64> {
        match self {
            EvalResult::Int(n) => Some(*n as f64),
            EvalResult::Float(f) => Some(*f),
            _ => None,
        }
    }
}

impl PartialEq for EvalResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (EvalResult::Int(a), EvalResult::Int(b)) => a == b,
            (EvalResult::Float(a), EvalResult::Float(b)) => a == b,
            (EvalResult::Int(a), EvalResult::Float(b)) => (*a as f64) == *b,
            (EvalResult::Float(a), EvalResult::Int(b)) => *a == (*b as f64),
            (EvalResult::Str(a), EvalResult::Str(b)) => a == b,
            (EvalResult::Bool(a), EvalResult::Bool(b)) => a == b,
            (EvalResult::Null, EvalResult::Null) => true,
            _ => false,
        }
    }
}

fn eval_value(expr: &Expr, context: &Value) -> Result<EvalResult, AuthzError> {
    match expr {
        Expr::Literal(lit) => Ok(match lit {
            LitValue::Int(n) => EvalResult::Int(*n),
            LitValue::Float(f) => EvalResult::Float(*f),
            LitValue::Str(s) => EvalResult::Str(s.clone()),
            LitValue::Bool(b) => EvalResult::Bool(*b),
        }),
        Expr::Path(segments) => {
            let mut current = context;
            for seg in segments {
                current = current.get(seg).unwrap_or(&Value::Null);
            }
            Ok(json_to_eval(current))
        }
        Expr::UnaryNot(inner) => {
            let val = eval_value(inner, context)?;
            match val {
                EvalResult::Bool(b) => Ok(EvalResult::Bool(!b)),
                _ => Err(AuthzError::InvalidCondition(
                    "`!` operator requires a boolean operand".into(),
                )),
            }
        }
        Expr::In {
            element,
            collection,
        } => {
            let elem = eval_value(element, context)?;
            let coll = eval_value(collection, context)?;
            match coll {
                EvalResult::Array(items) => Ok(EvalResult::Bool(items.contains(&elem))),
                _ => Err(AuthzError::InvalidCondition(
                    "`in` operator requires an array on the right side".into(),
                )),
            }
        }
        Expr::BinOp { op, left, right } => {
            let l = eval_value(left, context)?;
            let r = eval_value(right, context)?;
            match op {
                BinOp::And => match (&l, &r) {
                    (EvalResult::Bool(a), EvalResult::Bool(b)) => Ok(EvalResult::Bool(*a && *b)),
                    _ => Err(AuthzError::InvalidCondition(
                        "`&&` requires boolean operands".into(),
                    )),
                },
                BinOp::Or => match (&l, &r) {
                    (EvalResult::Bool(a), EvalResult::Bool(b)) => Ok(EvalResult::Bool(*a || *b)),
                    _ => Err(AuthzError::InvalidCondition(
                        "`||` requires boolean operands".into(),
                    )),
                },
                BinOp::Eq => Ok(EvalResult::Bool(l == r)),
                BinOp::Ne => Ok(EvalResult::Bool(l != r)),
                BinOp::Gt | BinOp::Lt | BinOp::Ge | BinOp::Le => {
                    let lf = l.as_f64().ok_or_else(|| {
                        AuthzError::InvalidCondition(
                            "comparison operator requires numeric operands".into(),
                        )
                    })?;
                    let rf = r.as_f64().ok_or_else(|| {
                        AuthzError::InvalidCondition(
                            "comparison operator requires numeric operands".into(),
                        )
                    })?;
                    let result = match op {
                        BinOp::Gt => lf > rf,
                        BinOp::Lt => lf < rf,
                        BinOp::Ge => lf >= rf,
                        BinOp::Le => lf <= rf,
                        _ => unreachable!(),
                    };
                    Ok(EvalResult::Bool(result))
                }
            }
        }
    }
}

fn json_to_eval(value: &Value) -> EvalResult {
    match value {
        Value::Null => EvalResult::Null,
        Value::Bool(b) => EvalResult::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                EvalResult::Int(i)
            } else if let Some(f) = n.as_f64() {
                EvalResult::Float(f)
            } else {
                EvalResult::Null
            }
        }
        Value::String(s) => EvalResult::Str(s.clone()),
        Value::Array(arr) => EvalResult::Array(arr.iter().map(json_to_eval).collect()),
        Value::Object(_) => EvalResult::Null, // objects not directly comparable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_simple_comparison() {
        let expr = parse_condition("x == 5").unwrap();
        assert_eq!(
            expr,
            Expr::BinOp {
                op: BinOp::Eq,
                left: Box::new(Expr::Path(vec!["x".into()])),
                right: Box::new(Expr::Literal(LitValue::Int(5))),
            }
        );
    }

    #[test]
    fn test_parse_dot_path() {
        let expr = parse_condition("request.time.hour >= 9").unwrap();
        assert_eq!(
            expr,
            Expr::BinOp {
                op: BinOp::Ge,
                left: Box::new(Expr::Path(vec![
                    "request".into(),
                    "time".into(),
                    "hour".into()
                ])),
                right: Box::new(Expr::Literal(LitValue::Int(9))),
            }
        );
    }

    #[test]
    fn test_parse_boolean_and() {
        let expr = parse_condition("a > 1 && b < 2").unwrap();
        match expr {
            Expr::BinOp { op: BinOp::And, .. } => {}
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn test_parse_in_operator() {
        let expr = parse_condition("request.ip in context.allowed_ips").unwrap();
        match expr {
            Expr::In { .. } => {}
            _ => panic!("expected In"),
        }
    }

    #[test]
    fn test_parse_not_operator() {
        let expr = parse_condition("!disabled").unwrap();
        match expr {
            Expr::UnaryNot(_) => {}
            _ => panic!("expected UnaryNot"),
        }
    }

    #[test]
    fn test_parse_parentheses() {
        let expr = parse_condition("(a || b) && c").unwrap();
        match expr {
            Expr::BinOp {
                op: BinOp::And,
                left,
                ..
            } => match *left {
                Expr::BinOp { op: BinOp::Or, .. } => {}
                _ => panic!("expected Or inside parens"),
            },
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn test_parse_string_literal() {
        let expr = parse_condition(r#"name == "alice""#).unwrap();
        assert_eq!(
            expr,
            Expr::BinOp {
                op: BinOp::Eq,
                left: Box::new(Expr::Path(vec!["name".into()])),
                right: Box::new(Expr::Literal(LitValue::Str("alice".into()))),
            }
        );
    }

    #[test]
    fn test_evaluate_comparison() {
        let expr = parse_condition("request.time.hour >= 9").unwrap();
        let ctx = json!({ "request": { "time": { "hour": 14 } } });
        assert!(evaluate(&expr, &ctx).unwrap());

        let ctx2 = json!({ "request": { "time": { "hour": 7 } } });
        assert!(!evaluate(&expr, &ctx2).unwrap());
    }

    #[test]
    fn test_evaluate_boolean_and() {
        let expr = parse_condition("request.time.hour >= 9 && request.time.hour < 17").unwrap();
        let ctx = json!({ "request": { "time": { "hour": 14 } } });
        assert!(evaluate(&expr, &ctx).unwrap());

        let ctx2 = json!({ "request": { "time": { "hour": 20 } } });
        assert!(!evaluate(&expr, &ctx2).unwrap());
    }

    #[test]
    fn test_evaluate_in_array() {
        let expr = parse_condition("request.ip in context.corporate_ips").unwrap();
        let ctx = json!({
            "request": { "ip": "10.0.0.1" },
            "context": { "corporate_ips": ["10.0.0.1", "10.0.0.2"] }
        });
        assert!(evaluate(&expr, &ctx).unwrap());

        let ctx2 = json!({
            "request": { "ip": "192.168.1.1" },
            "context": { "corporate_ips": ["10.0.0.1", "10.0.0.2"] }
        });
        assert!(!evaluate(&expr, &ctx2).unwrap());
    }

    #[test]
    fn test_evaluate_not() {
        let expr = parse_condition("!disabled").unwrap();
        let ctx = json!({ "disabled": false });
        assert!(evaluate(&expr, &ctx).unwrap());

        let ctx2 = json!({ "disabled": true });
        assert!(!evaluate(&expr, &ctx2).unwrap());
    }

    #[test]
    fn test_evaluate_string_eq() {
        let expr = parse_condition(r#"role == "admin""#).unwrap();
        let ctx = json!({ "role": "admin" });
        assert!(evaluate(&expr, &ctx).unwrap());

        let ctx2 = json!({ "role": "user" });
        assert!(!evaluate(&expr, &ctx2).unwrap());
    }

    #[test]
    fn test_evaluate_or() {
        let expr = parse_condition("a == 1 || b == 2").unwrap();
        assert!(evaluate(&expr, &json!({"a": 1, "b": 0})).unwrap());
        assert!(evaluate(&expr, &json!({"a": 0, "b": 2})).unwrap());
        assert!(!evaluate(&expr, &json!({"a": 0, "b": 0})).unwrap());
    }

    #[test]
    fn test_invalid_empty_expression() {
        assert!(parse_condition("").is_err());
    }

    #[test]
    fn test_invalid_unterminated_string() {
        assert!(parse_condition(r#""hello"#).is_err());
    }
}
