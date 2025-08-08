#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        println!("[ ETA ]: {} {}", ansi_term::Colour::Red.bold().paint("[!]"), $name)
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        if !$greppable {
            if $accessible {
                println!("[ ETA ]: {}", $name);
            } else {
                println!("[ ETA ]: {} {}", ansi_term::Colour::Red.bold().paint("[!]"), $name)
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        println!("[ ETA ]: {} {}", ansi_term::Colour::Blue.bold().paint("[!]"), $name)
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        if !$greppable {
            if $accessible {
                println!("[ ETA ]: {}", $name);
            } else {
                println!("[ ETA ]: {} {}", ansi_term::Colour::Blue.bold().paint("[!]"), $name)
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        println!("[ ETA ]: {} {}", ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"), $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        if !$greppable {
            if $accessible {
                println!("[ ETA ]: {}", $name);
            } else {
                println!("[ ETA ]: {} {}", ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"), $name);
            }
        }
    };
}

#[macro_export]
macro_rules! opening {
    () => {
        use rand::seq::IndexedRandom;
        let quotes = vec!["أعوذ بالله من الشيطان الرجيم بسم الله الرحمن الرحيم", "Arwah Network & PORTS IP SERVER Scanner & Sniffer Traffic"];
        let random_quote = quotes.choose(&mut rand::rng()).unwrap();
        println!("{}\n", random_quote);
    };
}
