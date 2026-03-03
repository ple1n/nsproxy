
I found that kernel reuses network namespaces of dead processes.

Therefore running `sproxy veth` consecutively results in one node with multiple veths, with some of them non existent.

# Accidental unsandboxeed process launches

One of the most common ways I leaked my IP was by launching browsers through unintended ways like opening a link or the launcher of KDE.

I tried wrapping librewolf browser with a wrapper binary and thought about kernel hooking to prevent such leaks. 

I reached a conclusion that _state isolation_ is the superior method.

That the anonymous identity is at its core, a form of secret state that should not be leaked into an uncontainerized network. 

In base system, the censor has no way to tell that I possess a secret material (state) that could identify myself as some identity.

Specifically, nsproxy should handle the environment through kernel namespaces, bind mounts, and chroot. 

In the base system, the browser launch can not leak my secret identity because the profile folder is not mounted.

Some basic anonymization. Anonymized user name, root directory paths for containers.

UplinkHub should track the IP quality of proxies. Blocked by google or not, and other sites.