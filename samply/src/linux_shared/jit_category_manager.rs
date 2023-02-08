use fxprof_processed_profile::{CategoryColor, CategoryPairHandle, Profile};

#[derive(Debug, Clone, Default)]
pub struct JitCategoryManager {
    generic_jit: Option<CategoryPairHandle>,
    interpreter: Option<CategoryPairHandle>,
    baseline: Option<CategoryPairHandle>,
    maglev: Option<CategoryPairHandle>,
    turbolift: Option<CategoryPairHandle>,
    ion: Option<CategoryPairHandle>,
    ic: Option<CategoryPairHandle>,
    trampoline: Option<CategoryPairHandle>,
}

impl JitCategoryManager {
    #[allow(unused)]
    pub fn new() -> Self {
        Self::default()
    }

    fn generic_jit(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.generic_jit, "JIT", CategoryColor::LightGreen)
    }

    fn interpreter(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(
            &mut self.interpreter,
            "Interpreter",
            CategoryColor::LightBlue,
        )
    }

    fn baseline(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.baseline, "Baseline", CategoryColor::Blue)
    }

    fn maglev(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.maglev, "Maglev", CategoryColor::Purple)
    }

    fn turbolift(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.turbolift, "Turbolift", CategoryColor::Red)
    }

    fn ion(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.ion, "Ion", CategoryColor::Red)
    }

    fn ic(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.ic, "IC", CategoryColor::Brown)
    }

    fn trampoline(&mut self, profile: &mut Profile) -> CategoryPairHandle {
        profile.ensure_category(&mut self.trampoline, "Trampoline", CategoryColor::DarkGray)
    }

    pub fn get_category(
        &mut self,
        symbol_name: Option<&str>,
        profile: &mut Profile,
    ) -> CategoryPairHandle {
        if let Some(symbol_name) = symbol_name {
            if symbol_name.starts_with("JS:~") {
                self.interpreter(profile)
            } else if symbol_name.starts_with("JS:^") {
                self.baseline(profile)
            } else if symbol_name.starts_with("JS:+") {
                self.maglev(profile)
            } else if symbol_name.starts_with("JS:*") {
                self.turbolift(profile)
            } else if symbol_name.starts_with("Baseline: ") {
                self.baseline(profile)
            } else if symbol_name.starts_with("Ion: ") {
                self.ion(profile)
            } else if symbol_name.starts_with("IC: ") {
                self.ic(profile)
            } else if symbol_name.starts_with("Trampoline: ") {
                self.trampoline(profile)
            } else {
                self.generic_jit(profile)
            }
        } else {
            self.generic_jit(profile)
        }
    }
}

trait EnsureCategory {
    fn ensure_category(
        &mut self,
        storage: &mut Option<CategoryPairHandle>,
        name: &str,
        color: CategoryColor,
    ) -> CategoryPairHandle;
}

impl EnsureCategory for Profile {
    fn ensure_category(
        &mut self,
        storage: &mut Option<CategoryPairHandle>,
        name: &str,
        color: CategoryColor,
    ) -> CategoryPairHandle {
        *storage.get_or_insert_with(|| self.add_category(name, color).into())
    }
}
