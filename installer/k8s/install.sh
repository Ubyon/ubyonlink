#!/bin/bash

set -e
#set -x

usage="""usage: $0 [options]

Options:
  -h  This help message.
  -d  Output directory for installation generated files.
  -t  Ubyon TrustGate FQDN that AppConnector connects to.
  -k  Enable k8s access
"""

UBYON_TG_FQDN="ulink.ubyon.com"
OUTDIR="."

while getopts "hd:t:k:" opt; do
  case "$opt" in
    h)
      echo -e "$usage"
      exit 0
      ;;
    d)
      OUTDIR="$OPTARG"
      ;;
    t)
      UBYON_TG_FQDN="$OPTARG"
      ;;
    k)
      ENABLE_K8S_ACCESS="$OPTARG"
      ;;
    *)
      echo
      echo -e "$usage" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))

disable_k8s_access()
{
  kubectl delete -f https://raw.githubusercontent.com/Ubyon/ubyonlink/main/installer/k8s/k8s_sa.yaml
}

enable_k8s_access()
{
  kubectl apply -f https://raw.githubusercontent.com/Ubyon/ubyonlink/main/installer/k8s/k8s_sa.yaml
  NAMESPACE=default
  SECRET_NAME=ubyon-api-service-account-token
  K8S_SA_TOKEN=$(kubectl get secret --namespace "${NAMESPACE}" "${SECRET_NAME}" -o json | jq -r '.data["token"]' | base64 -d)
  echo "$K8S_SA_TOKEN"
  export K8S_SA_TOKEN
  kubectl get cm ubyonac -o yaml | sed 's/k8s_sa_token: <k8s_sa_token>/k8s_sa_token: '"$K8S_SA_TOKEN"'/g' | kubectl apply -f -
}

if [ "$ENABLE_K8S_ACCESS" == true ]; then
  echo "Enabling kubernetes access !!!!"
  enable_k8s_access
  exit
elif [ "$ENABLE_K8S_ACCESS" == false ]; then
  disable_k8s_access
  exit
fi

INSTALL_FINISHED="$OUTDIR/.install_ubyonac"

if [ -f $INSTALL_FINISHED ] ; then
  echo "Install has already finished."
  exit
fi

install_basic_packages()
{
  if ! [ -x "$(command -v uuidgen)" ] ; then
    echo "==> Install basic OS packages."
    sudo apt-get update > /dev/null
    sudo apt-get install -y uuid-runtime > /dev/null
  fi
}

install_k8s_container()
{
  echo "==> Install k8s container."

  local mars_cluster_id="$1"
  local mars_ulink_endpoint="$2"

  cat > $OUTDIR/ubyonac.yaml <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ubyonac
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ubyonac
  serviceName: ubyonac
  template:
    metadata:
      labels:
        app: ubyonac
        version: 1.0.0
    spec:
      hostNetwork: true
      containers:
      - name: ubyonac
        imagePullPolicy: Always
        image: quay.io/ubyon/mars-ulink:1.0.0
        command: ["/home/ubyon/bin/mars"]
        args: ["--mars_cluster_id=$mars_cluster_id",
               "--mars_ulink_endpoint=$mars_ulink_endpoint",
               "--v=0"]
        env:
          - name: MY_POD_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: MY_POD_NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: MY_POD_IP
            valueFrom:
              fieldRef:
                fieldPath: status.podIP
EOF

  kubectl apply -f $OUTDIR/ubyonac.yaml
}

install_ubyonac()
{
  install_basic_packages
  
  local ulink_id=$(uuidgen)
  local host_name=$(hostname)
  local reg_info="{\"ulinkId\":\"$ulink_id\",\"ulinkName\":\"$host_name\"}"
  local base64_reg_info=`echo -n $reg_info | base64 -w0`

  install_k8s_container $ulink_id $UBYON_TG_FQDN

  echo
  echo "==> Installation completed successfully."
  echo "Please register your Ubyon AppConnector via: "
  echo "  https://manage.ubyon.com/admin-portal/ulink/register?reg_info=$base64_reg_info"
}

mkdir -p "$OUTDIR"

install_ubyonac

touch $INSTALL_FINISHED

echo
