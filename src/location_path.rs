const OPEN_CHAR: char = '{';
const CLOSE_CHAR: char = '}';
const SEPARATOR: char = ',';
const ESCAPE: char = '\\';

#[derive(Debug, PartialEq, Clone)]
enum Token {
    Open,
    Close,
    Separator,
    Payload(String),
    Branches(Branches),
}

impl From<char> for Token {
    fn from(ch: char) -> Token {
        match ch {
            OPEN_CHAR => Token::Open,
            CLOSE_CHAR => Token::Close,
            SEPARATOR => Token::Separator,
            _ => panic!("Non tokenizable char!"),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
struct Branches {
    tokens: Vec<Vec<Token>>,
}

impl Branches {
    fn new() -> Branches {
        Branches { tokens: Vec::new() }
    }

    fn add_branch(&mut self, branch: Vec<Token>) {
        self.tokens.push(branch);
    }

    fn from(tokens: &[Token]) -> Branches {
        let mut branches = Branches::new();
        let mut tail = tokens.to_owned();
        while let Some(pos) = tail.iter().position(|token| *token == Token::Separator) {
            let mut rest = tail.split_off(pos);
            branches.add_branch(tail);
            rest.remove(0);
            tail = rest;
        }
        branches.add_branch(tail);
        branches
    }
}

impl From<Branches> for Token {
    fn from(branches: Branches) -> Token {
        Token::Branches(branches)
    }
}

impl From<Vec<Token>> for Branches {
    fn from(tokens: Vec<Token>) -> Branches {
        Branches::from(&tokens)
    }
}

impl From<Token> for String {
    fn from(token: Token) -> String {
        match token {
            Token::Branches(_) => panic!("Cannot convert to String!"),
            Token::Payload(text) => text,
            Token::Open => OPEN_CHAR.to_string(),
            Token::Close => CLOSE_CHAR.to_string(),
            Token::Separator => SEPARATOR.to_string(),
        }
    }
}

impl From<Branches> for Vec<String> {
    fn from(branches: Branches) -> Vec<String> {
        let Branches { tokens: token_lines } = branches;
        let mut vec: Vec<String> = Vec::new();
        let braces = token_lines.len() == 1;

        for tokens in token_lines {
            let mut vec_string = output(tokens);
            vec.append(&mut vec_string);
        }
        if braces {
            vec.iter()
                .map(|line| format!("{OPEN_CHAR}{line}{CLOSE_CHAR}"))
                .collect::<Vec<String>>()
        } else {
            vec
        }
    }
}

fn output(tokens: Vec<Token>) -> Vec<String> {
    let mut output: Vec<String> = vec![String::new()];
    for token in tokens {
        let mut aux: Vec<String> = Vec::new();
        let strings: Vec<String> = token.into();
        for root in &output {
            for string in &strings {
                aux.push(format!("{root}{string}"));
            }
        }
        output = aux;
    }
    output
}

impl From<Token> for Vec<String> {
    fn from(token: Token) -> Vec<String> {
        match token {
            Token::Branches(branches) => branches.into(),
            _ => {
                let frag: String = token.into();
                vec![frag]
            }
        }
    }
}

fn tokenize(string: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut chars = string.chars();
    let mut payload = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            OPEN_CHAR | SEPARATOR | CLOSE_CHAR => {
                if !payload.is_empty() {
                    tokens.push(Token::Payload(payload));
                }
                payload = String::new();
                if ch == CLOSE_CHAR {
                    let pos = tokens.iter().rposition(|token| *token == Token::Open);
                    if let Some(pos) = pos {
                        let branches: Branches = {
                            let mut to_branches = tokens.split_off(pos);
                            to_branches.remove(0);
                            to_branches
                        }
                        .into();
                        tokens.push(branches.into());
                    } else {
                        tokens.push(ch.into());
                    }
                } else {
                    tokens.push(ch.into());
                }
            }
            ESCAPE => {
                payload.push(ch);
                if let Some(next_char) = chars.next() {
                    payload.push(next_char);
                }
            }
            _ => payload.push(ch),
        }
    }
    let payload = payload.trim_end();
    if !payload.is_empty() {
        tokens.push(Token::Payload(payload.into()));
    }
    tokens
}

pub fn expand_path(path: &str) -> Vec<String> {
    output(tokenize(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reduce(s: &str) -> String {
        let v = expand_path(s);
        v[1..].iter().fold(v[0].to_string(), |acc, e| acc + ", " + e)
    }

    #[test]
    fn simple() {
        assert_eq!(reduce("/abc.html"), "/abc.html");
        assert_eq!(reduce("/abc}.html"), "/abc}.html");
        assert_eq!(reduce("/{abc}.html"), "/{abc}.html");
    }

    #[test]
    fn expand() {
        assert_eq!(
            reduce("/{abc,d{e,f}}.html"),
            "/abc.html, /de.html, /df.html".to_string()
        );

        assert_eq!(reduce("/{abc,d{e,f}.html"), "/{abc,de.html, /{abc,df.html".to_string());

        assert_eq!(
            reduce("It{{em,alic}iz,erat}e{d,}, please."),
            format!(
                "{}{}",
                "Itemized, please., Itemize, please., Italicized, please., Italicize, please., ",
                "Iterated, please., Iterate, please."
            )
        );

        assert_eq!(
            reduce(r"{}} some }{,{\\{ edge, edge} \,}{ cases, {here} \\\\\}"),
            r"{}} some }{,{\\ edge \,}{ cases, {here} \\\\\}, {}} some }{,{\\ edge \,}{ cases, {here} \\\\\}"
                .to_string()
        );
    }
}
