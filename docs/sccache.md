Before caching.

```
~/nsp3 (main)> cargo clean 
     Removed 230184 files, 293.8GiB total
⏎                                       
```

Fresh build with sccache and shared cargo directory produces

```
/data/check-cargo-storage.sh
11G     /data/cargo-target
991M    /data/sccache
```