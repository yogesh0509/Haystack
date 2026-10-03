# UX

This page records what the Bitcoin Design Guide recommends and how the demo applies it. Related work
and what it adds to the plan are in `docs/05-prior-art.md` (positioning notes) and
`docs/04-roadmap.md`, "After the hackathon" (build items).

## The Bitcoin Design Guide, applied

The [Bitcoin Design Guide](https://bitcoin.design/guide/) is the community's reference for designing
Bitcoin products. The table pairs each recommendation the demo follows with what the demo does. The
guide never discusses what an Electrum server learns, so the closest statements on that are listed
after the table.

| Recommendation | Page | What the demo does |
|---|---|---|
| "Use plain language that people new to bitcoin can understand regardless of prior knowledge" and "Educate in place, when people are presented with a new concept" | [Principles](https://bitcoin.design/guide/getting-started/principles/), Inclusion | Each score has a plain sentence under it ("Its 133 best guesses hold 13.3 real addresses; random guessing gets 13.3"). The formulas sit in "How the score is computed". T1 and T2 appear only in small text, so readers can match the page to these docs. |
| "Explain what risks the user is taking on, and how best to mitigate them" | [Principles](https://bitcoin.design/guide/getting-started/principles/), Transparency | The coin-history number is as large as the bits number and has its own word ("exposed"). The Wallet tab repeats both words. The chain-decoy caveat appears as soon as chain decoys are used. |
| "While scanning takes place, applications should show progress and the estimated completion time." | [Silent payments](https://bitcoin.design/guide/how-it-works/silent-payments/) | "Syncing privately… 12 s (the last one took 25.6 s)". The previous sync's duration is the estimate. |
| "Users should not be forced to wait until transaction completion to keep using the wallet" | [Sending](https://bitcoin.design/guide/daily-spending-wallet/sending/) | Syncs, payments and blocks run in the background. The page keeps updating, and a button that would conflict is disabled with the reason shown next to it. |
| "the default unit for on-chain wallets should be bitcoin with 8 decimal places" and "Clearly separating digit groups with a thin space and/or color can help more quickly understand how large or small a number is." | [Units and symbols](https://bitcoin.design/guide/designing-products/units-and-symbols/) | Amounts read `0.004 000 00 BTC`, with tabular digits. |
| "make secondary details easily accessible" | [Activity](https://bitcoin.design/guide/daily-spending-wallet/activity/) | The Wallet tab carries the summary. The Lab tab and the expandable sections carry the evidence. |
| "privacy should be incorporated and built into products by default" | [Wallet privacy](https://bitcoin.design/guide/how-it-works/wallet-privacy/) | The Wallet tab is the Haystack wallet, with the badge "Private sync on". The plain copy exists only in the Lab, as the contrast. |
| "there is often an inherent tension between creating something easy to understand and something that is technically accurate" | [Saving Satoshi](https://bitcoin.design/guide/case-studies/saving-satoshi/) | The grid draws the attacker's actual probability for every address the server received. It is a measurement, not an illustration. |
