Trying to reproduce the bug described in https://github.com/gitpod-io/leeway/issues/100 but I haven't been able to so far.

```sh
cd /workspace/leeway/fixtures/dynamic-components
run ../../main.go exec --transitive-dependencies --components --parallel --package not-dynamic:echo -- ls -al
[dynamic] total 8
[dynamic] drwxr-xr-x 2 gitpod gitpod  65 Sep 29 11:18 .
[dynamic] drwxr-xr-x 4 gitpod gitpod  62 Sep 29 11:10 ..
[dynamic] -rw-r--r-- 1 gitpod gitpod 699 Sep 29 11:23 BUILD.js
[dynamic] -rw-r--r-- 1 gitpod gitpod   0 Sep 29 11:10 BUILD.yaml
[dynamic] -rw-r--r-- 1 gitpod gitpod  21 Sep 29 11:13 message-input.txt
[not-dynamic] total 4
[not-dynamic] drwxr-xr-x 2 gitpod gitpod  24 Sep 29 11:18 .
[not-dynamic] drwxr-xr-x 4 gitpod gitpod  62 Sep 29 11:10 ..
[not-dynamic] -rw-r--r-- 1 gitpod gitpod 213 Sep 29 11:21 BUILD.yaml
```
