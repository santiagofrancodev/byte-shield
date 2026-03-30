# Ejemplo mínimo: despliega el chart Helm en un clúster existente.
# Requiere: kubectl configurado o provider kubernetes/helm.

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
}

variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

provider "helm" {
  kubernetes {
    config_path = pathexpand(var.kubeconfig_path)
  }
}

resource "helm_release" "byteshield" {
  name       = "byteshield"
  chart      = "${path.module}/../../helm/byteshield"
  namespace  = "default"
  version    = "0.1.0"
  depends_on = []
}
