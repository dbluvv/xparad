pub struct Checkpoint {
    pub height: u64,
    pub hash: &'static str,
}
pub const COIN_NAME: &str = "xPARASITE";
pub const COIN_SYMBOL: &str = "xPARA";
pub const UNLOCK_OFFSET: u64 = 3;
pub const FIX_BC_OFFSET: u64 = 1;
pub const CHECKPOINTS: [Checkpoint; 7] = [
	Checkpoint { height: 15000, hash: "0065116f7a959953bc5863bfdd633c0cec0f4d79eafcb48c6c15f5f64551be23" },
    Checkpoint { height: 30000, hash: "5db439b4af3f4e8a000c6172b5eb9052d1514e289983db74abd59564a621ca95" },
	Checkpoint { height: 45000, hash: "02c70472fea6c83bf1d314faf8373131f4b2cc783c8cdd738cf2e1dbeba991c7" },
	Checkpoint { height: 60000, hash: "f63af761b0b9803ed738e301bfcdc79c825964d43ebfb80a8aa135c9e9c40250" },
	Checkpoint { height: 75000, hash: "bbea79eb231664fc22b4795869b72b3ce456e28faf6e25facb12eca259481199" },
	Checkpoint { height: 90000, hash: "1ad259c05d8d3a84f64901772cd281e8df8b8b5e4c52ea10909d381d14737863" },
	Checkpoint { height: 103908, hash: "828f1f3772f6d88bf42b4cf17658e846ded351debc4e06803fc59a25ee0cb985"},
];