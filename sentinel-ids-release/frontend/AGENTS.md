<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Application architecture
- Keep security session state in the shared WorkspaceProvider, so navigation preserves flow analysis and alert review.
- Keep flow parsing and rule evaluation in the browser-safe sentinel module, so CSV analysis requires no external service.
- Use Papa Parse for CSV reading and writing, so quoted values and headers are handled consistently.
- Represent each workspace view as its own TanStack leaf route with page-specific metadata, so views can be linked directly.
- Keep simulation and rule-analysis provenance on every flow, so the interface never confuses demo results with measured inference.
