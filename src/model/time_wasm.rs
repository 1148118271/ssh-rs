use std::cmp::Ordering;
pub struct Instant {
    start_time:u64
}
impl Instant {
    pub(crate) fn now() -> Instant {
        // js_sys::Date::now()
        let time =  js_sys::Date::now();
        // let date = js_sys::Date::new(js_sys::)
        Instant { start_time: time as u64}
    }

    pub(crate) fn elapsed(&self) -> Duration {
        let time =  js_sys::Date::now() as u64;
        return Duration{
            milliseconds: time - self.start_time 
        };
    }
}

#[derive(Clone, Copy)]
pub struct Duration {
    milliseconds : u64,
}

impl PartialOrd<Duration> for Duration {
    fn partial_cmp(&self, other: &Duration) -> Option<std::cmp::Ordering> {
        if self.milliseconds > other.milliseconds {
            Some(Ordering::Greater)
        } else if other.milliseconds > self.milliseconds {
            Some(Ordering::Less)
        }else {
            Some(Ordering::Equal)
        }
    }
}

impl PartialEq<Duration> for Duration {
    fn eq(&self, other: &Duration) -> bool {
        self.milliseconds > other.milliseconds
    }
}

impl Duration {
    pub(crate) fn from_secs(seconds: i32) -> Duration {
        Duration {
            milliseconds: (seconds*1000).try_into().unwrap()
        }
    }

    pub(crate) fn to_sys_duration(&self) -> instant::Duration {
        return instant::Duration::from_millis(self.milliseconds);
    }
}
