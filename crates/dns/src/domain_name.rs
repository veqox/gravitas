use std::fmt::Display;

#[derive(Debug)]
pub struct DomainName<'a> {
    pub labels: Vec<&'a str>,
}

impl<'a> DomainName<'a> {
    pub fn from_labels(labels: Vec<&'a str>) -> Self {
        Self { labels }
    }

    pub fn size(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum()
    }
}

impl Default for DomainName<'_> {
    fn default() -> Self {
        Self { labels: Vec::new() }
    }
}

impl Display for DomainName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::with_capacity(self.size());

        for (i, part) in self.labels.iter().enumerate() {
            if i > 0 {
                result.push('.');
            }
            result.push_str(part);
        }

        result.push('.');

        f.write_str(&result)
    }
}
