use std::fmt::Debug;

pub struct DomainName<'a> {
    pub labels: Vec<&'a str>,
}

impl<'a> DomainName<'a> {
    pub fn from_labels(labels: Vec<&'a str>) -> Self {
        Self { labels }
    }

    pub fn to_string(&self) -> String {
        let mut result = String::new();

        for (i, part) in self.labels.iter().enumerate() {
            if i > 0 {
                result.push('.');
            }
            result.push_str(part);
        }

        result.push('.');
        result
    }
}

impl<'a> Debug for DomainName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}
