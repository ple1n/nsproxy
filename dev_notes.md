
To release a new version 

```sh
./strip.sh
gh release create v2.1.0 ./release/*
```

# What could be added

- pivot_root, wip
- automatic retries of proxy connection at nsproxy's side, which suits the case where the software does not handle connection failures well in poor network condition

# Method

I prefer json over yaml, toml, or xml, as a person who is familiar with all of them. 

These so-called better formats are poorly readable, often ambiguous, counter-intuitive leading to reduced productivity.

# Opsec as a multi-variable optimization problem

For a long time people have pursued opsec through paranoid hardware hardening, resorting to some very niche pick of setup. 

Opsec is a multi-variable problem. It's not called a compromise between usability and anonymity. It's called a saddle point on the multi-variable optimization problem.