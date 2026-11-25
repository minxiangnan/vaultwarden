//! Alias lookup. An exact alias always wins. Otherwise a single strong fuzzy match is used.
//! Two or more plausible matches are an ambiguity error and do not return a code.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasFields {
    pub alias: String,
    pub issuer: String,
    pub account: String,
    pub host: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub alias: String,
    pub issuer: String,
    pub account: String,
    pub host: String,
    pub score: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolve {
    Match {
        index: usize,
        kind: &'static str,
    },
    Ambiguous(Vec<Candidate>),
    None,
}

pub fn normalize_alias(raw: &str) -> Result<String, &'static str> {
    let alias = raw.trim().to_lowercase();
    if alias.chars().any(char::is_whitespace) {
        return Err("别名不能包含空格");
    }
    if alias.is_empty() || alias.len() > 64 {
        return Err("别名需要 1 到 64 个字符");
    }
    let mut chars = alias.chars();
    let Some(first) = chars.next() else {
        return Err("别名需要 1 到 64 个字符");
    };
    if !first.is_ascii_alphanumeric() {
        return Err("别名要以字母或数字开头");
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err("别名只能包含字母、数字、点、下划线和连字符");
    }
    Ok(alias)
}

pub fn resolve(query: &str, entries: &[AliasFields]) -> Resolve {
    let query = normalize_query(query);
    if query.is_empty() {
        return Resolve::None;
    }
    if let Some(index) = entries.iter().position(|entry| entry.alias == query) {
        return Resolve::Match {
            index,
            kind: "exact",
        };
    }

    let mut scored: Vec<(usize, i32)> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| score(&query, entry).map(|score| (index, score)))
        .collect();
    if scored.is_empty() {
        return Resolve::None;
    }
    scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| entries[a.0].alias.cmp(&entries[b.0].alias)));
    let best = scored[0].1;
    let second = scored.get(1).map_or(0, |item| item.1);
    if scored.len() == 1 || (best >= 80 && best > second) {
        return Resolve::Match {
            index: scored[0].0,
            kind: "fuzzy",
        };
    }
    Resolve::Ambiguous(scored.into_iter().map(|(index, score)| candidate(&entries[index], score)).collect())
}

fn candidate(entry: &AliasFields, score: i32) -> Candidate {
    Candidate {
        alias: entry.alias.clone(),
        issuer: entry.issuer.clone(),
        account: entry.account.clone(),
        host: entry.host.clone(),
        score,
    }
}

fn normalize_query(query: &str) -> String {
    query.trim().chars().filter(|c| !c.is_whitespace()).flat_map(char::to_lowercase).collect()
}

fn score(query: &str, entry: &AliasFields) -> Option<i32> {
    let mut best = 0;
    best = best.max(contains_score(&entry.alias, query, 80));
    for field in [&entry.issuer, &entry.account, &entry.host] {
        let field = normalize_query(field);
        if field.is_empty() {
            continue;
        }
        if field == *query {
            best = best.max(75);
        }
        best = best.max(contains_score(&field, query, 55));
        if query.len() >= 4 && field.len() >= 4 && levenshtein(&field, query) <= 1 {
            best = best.max(70);
        }
    }
    if entry.alias.len() >= 4 && query.len() >= 4 && levenshtein(&entry.alias, query) <= 1 {
        best = best.max(70);
    }
    (best >= 50).then_some(best)
}

fn contains_score(haystack: &str, query: &str, score: i32) -> i32 {
    if query.len() < 2 || haystack.len() < 2 {
        return 0;
    }
    if haystack.contains(query) || query.contains(haystack) {
        score
    } else {
        0
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<AliasFields> {
        vec![
            AliasFields {
                alias: "gitlab".into(),
                issuer: "GitLab".into(),
                account: "ada".into(),
                host: "gitlab.com".into(),
            },
            AliasFields {
                alias: "github".into(),
                issuer: "GitHub".into(),
                account: "ada".into(),
                host: "github.com".into(),
            },
            AliasFields {
                alias: "oxylabs".into(),
                issuer: "Oxylabs".into(),
                account: "proxy".into(),
                host: String::new(),
            },
        ]
    }

    #[test]
    fn exact_alias_is_case_insensitive() {
        let found = resolve(" GitLab ", &entries());
        assert_eq!(
            found,
            Resolve::Match {
                index: 0,
                kind: "exact"
            }
        );
    }

    #[test]
    fn unique_fuzzy_host_matches_and_shared_account_is_ambiguous() {
        match resolve("gitlab.com", &entries()) {
            Resolve::Match {
                index,
                kind,
            } => {
                assert_eq!(index, 0);
                assert_eq!(kind, "fuzzy");
            }
            other => panic!("expected a unique host match, got {other:?}"),
        }
        match resolve("ada", &entries()) {
            Resolve::Ambiguous(candidates) => {
                let aliases: Vec<_> = candidates.iter().map(|c| c.alias.as_str()).collect();
                assert!(aliases.contains(&"gitlab"));
                assert!(aliases.contains(&"github"));
                assert!(!aliases.contains(&"oxylabs"));
            }
            other => panic!("expected an ambiguity error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_query_and_invalid_alias() {
        assert_eq!(resolve("nope", &entries()), Resolve::None);
        assert!(normalize_alias("GitLab").is_ok());
        assert_eq!(normalize_alias("GitLab").unwrap(), "gitlab");
        assert!(normalize_alias("-bad").is_err());
        assert!(normalize_alias("has space").is_err());
        assert!(normalize_alias("").is_err());
    }
}
