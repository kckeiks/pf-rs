use crate::rule::{Rule, Action};

#[derive(Debug)]
struct Filter {
    default_act: Action,
    rules: Option<Vec<Rule>>,
}

impl Filter {
    pub fn new() -> Self {
        Filter { default_act: Action::Pass, rules: Some(Vec::new()) }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.as_mut().map(|rules| rules.push(rule));
    }

    // load filter on iface
    pub fn load_on(rules: Vec<Rule>) -> Result<(), ()> {

        Ok(())
    }
}
