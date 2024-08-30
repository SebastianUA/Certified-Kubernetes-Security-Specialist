# Google Kubernetes Engine (GKE)

**[Google Kubernetes Engine (GKE)][gke]** easily lets you get a Kubernetes
cluster with Network Policies feature.

## Create a cluster

To create a GKE cluster named `gke-cluster` with Network Policy feature enabled, run:
```
gcloud container clusters create gke-cluster \
    --enable-network-policy \
    --zone us-central1-b
```

This will create a 3-node Kubernetes cluster on Kubernetes Engine.

Once you complete this tutorial, you can delete the cluster by running:
```
gcloud container clusters delete -q --zone us-central1-b np
```

## Additional useful material

[GKE]: https://cloud.google.com/kubernetes-engine/
