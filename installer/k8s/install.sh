#!/bin/bash

set -e
#set -x

usage="""usage: $0 [options]

Options:
  -h  This help message.
  -t  Ubyon TrustGate FQDN that AppConnector connects to.
"""

CA_CERT=
JWT_TOKEN=
UBYON_TG_FQDN=
SCRIPT_DIR=$(dirname $0)
MARS_ULINK_CONFIG_DIR=$(readlink -f "${SCRIPT_DIR}")/ubyonac/configs

while getopts "hp:t:" opt; do
  case "$opt" in
    h)
      echo -e "$usage"
      exit 0
      ;;
    t)
      UBYON_TG_FQDN="$OPTARG"
      ;;
    *)
      echo
      echo -e "$usage" 1>&2
      exit 1
      ;;
  esac
done

shift $((OPTIND - 1))

if [ $# != 0 ]; then
  echo
  echo -e "$usage" 1>&2
  echo
  exit -1
fi

if [ $(id -u) = 0 ] ; then
  echo
  echo "Cannot run $0 in root. Run in sudo user!"
  echo
  exit -1
fi

if ! [ -x "$(command -v kubectl)" ] ; then
  echo "Script requires kubernetes kubectl."
  exit
fi

INSTALL_FINISHED="$MARS_ULINK_CONFIG_DIR/ubyonac.yaml"
if [ -f $INSTALL_FINISHED ] ; then
  echo "Install has already finished."
  exit
fi

# Initialize TG endpoint if it is not specified from user.
if [ "$UBYON_TG_FQDN" == "" ] ; then
  UBYON_TG_FQDN="ulink.ubyon.com"
fi

install_packages()
{
  if ! [ -x "$(command -v uuidgen)" ] ; then
    echo "==> Install basic OS packages."
    sudo apt-get update > /dev/null
    sudo apt-get install -y uuid-runtime > /dev/null
  fi

  # Patch mars-ulink.yaml with the following attributes:
  #  -. Host name
  #  -. JWT token
  #
  mkdir -p $MARS_ULINK_CONFIG_DIR
  local mars_ulink_config_file=$MARS_ULINK_CONFIG_DIR/mars-ulink.yaml
  sudo tee $mars_ulink_config_file > /dev/null <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: ubyonac
  labels:
    app: ubyonac
data:
  mars-ulink.yaml: |-
    # Nmae of the UbyonLink.
    # name: <ulink_name>

    # Ssh principal.
    # principal: <principal>

    # Short-lived JWT token that can be used to registered with Ubyon Cloud.
    #
    # token: <jwt_token>

    # System and user defined labels in list of key/value format.
    labels:
      - service: ssh
      #- serial: <Serial Number>
EOF

  local user_name=$(id -un)
  local host_name=$(hostname)
  sudo sed -i "s/# name: .*/name: $host_name/" $mars_ulink_config_file
  sudo sed -i "s/# principal: .*/principal: $user_name/" $mars_ulink_config_file

  if [ "$JWT_TOKEN" != "" ] ; then
    sudo sed -i "s/# token: .*/token: $JWT_TOKEN/" $mars_ulink_config_file
  fi

  kubectl apply -f $mars_ulink_config_file
}

maybe_enable_cert_based_ssh()
{
  if [ "$CA_CERT" == "" ] ; then
    return
  fi

  echo "==> Enable cert based SSH."
  sudo tee /etc/ssh/ubyon_ca_cert.pub > /dev/null <<EOF
`echo -n $CA_CERT | base64 -d`
EOF

  sudo grep "TrustedUserCAKeys " /etc/ssh/sshd_config > /dev/null 2>&1 || \
    sudo tee -a /etc/ssh/sshd_config > /dev/null <<EOF
TrustedUserCAKeys /etc/ssh/ubyon_ca_cert.pub
EOF

  # ED25519 key should be one of the supported key.
  local accept_keys=$(sudo grep "PubkeyAcceptedKeyTypes" /etc/ssh/sshd_config || true)
  if [ "$accept_keys" != "" ] ; then
    echo $accept_keys | grep "ssh-ed25519-cert-v01@openssh.com" > /dev/null 2>&1 || \
      sudo sed -i "s/^PubkeyAcceptedKeyTypes .*/&,ssh-ed25519-cert-v01@openssh.com/" /etc/ssh/sshd_config
  fi

  sudo systemctl restart sshd
}

install_daemon()
{
  echo "==> Install k8s container."

  local mars_cluster_id="$1"
  local mars_ulink_endpoint="$2"

  # Deployment yaml.
  cat > $MARS_ULINK_CONFIG_DIR/ubyonac.yaml <<EOF
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
        volumeMounts:
          - name: ubyonac
            mountPath: /home/ubyon/configs
      volumes:
        - name: ubyonac
          configMap:
            name: ubyonac
            defaultMode: 0644
EOF

  kubectl apply -f $MARS_ULINK_CONFIG_DIR/ubyonac.yaml
}

install_ubyonac()
{
  # Install packages.
  install_packages || return
  
  # Install daemon service files and start the daemon.
  local ulink_id=$(uuidgen)
  install_daemon $ulink_id $UBYON_TG_FQDN || return

  maybe_enable_cert_based_ssh || return

  echo
  echo "==> Installation completed successfully."

  if [ "$JWT_TOKEN" == "" ] ; then
    echo
    echo "==> JWT token is required to register the ubyonac."
    echo "1. Please acquire a registration token via:"
    echo "     https://manage.ubyon.com/<token_path>"
    echo
    echo "2. Save the token into ${MARS_ULINK_CONFIG_DIR}/mars-ulink.yaml"
    echo "3. Reload ubyonac configmap and deployment using following command: "
    echo "     kubectl apply -f ${MARS_ULINK_CONFIG_DIR}/mars-ulink.yaml"
    echo "     kubectl apply -f ${MARS_ULINK_CONFIG_DIR}/ubyonac.yaml"
    echo
  else
    echo
    echo "==> Enjoy..."
    echo
  fi
}

install_ubyonac

echo
