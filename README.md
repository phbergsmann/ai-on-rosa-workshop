# OpenShift AI + Amazon Bedrock Workshop = Better together... An end-2-end solution for all your AI needs!
Join us for an exciting workshop where we explore the powerful combination of OpenShift AI and Amazon Bedrock—showing how they truly are better together! This hands-on session is designed specifically to work off an use-case (insurance), providing participants with guided labs and practical exercises to help uncover and implement AI-driven solutions.

# Transforming Claims Processing for Maximum Efficiency!
Get ready to dive into the future of insurance with Parasol, an innovative company using AI to supercharge the efficiency of claim processing! We're harnessing cutting-edge models and technologies to revolutionize how things are done.

In this workshop, you'll see firsthand how Natural Language Processing (NLP) and Large Language Models (LLMs) are transforming the user experience. But we’re not stopping there! Fine-tuning and comparing models? We’ve got that covered, too.

Throughout this hands-on exercise, you’ll explore how AI can simplify your workflows. From consulting models for information to performing image recognition and comparing model outputs, you'll experience the incredible capabilities AI has to offer.

And the best part? While we’re working with a predefined insurance use case, we’re confident the knowledge and skills you gain will be invaluable for your own AI projects.

Ready to collaborate with Red Hat and Amazon Web Services on your use case? We’re here to support you every step of the way—reach out, and let’s make it happen!

## Introduction

This repository contains the code, instructions, resources and materials associated with the Lab called **OpenShift AI + Amazon Bedrock Workshop**.

To consult the static version of the instructions, please use [this URL](https://rh-aiservices-bu.github.io/parasol-insurance/)

If you want to participate in the creation and update of this content, please consult the sections below.

<details>
  <summary>Display Development-centric information</summary>

## General Development Information

### Working with this repo

- `main` branch is the one used for production. That's where the Prod and Test catalog items from [demo.redhat.com](https://demo.redhat.com) point to (instructions, materials used,...).
- `dev` branch is for development. That's where the Dev catalog item points to.
- Branches are made from `dev` (hot fixes could be made from `main` if really needed).
- When ready, PRs should be made to `dev`. Once all features, bug fixes,... are checked in and tested for a new release, another PR will be made from `dev` to `main`.
- Branches must be prefixed with `/feature` (example `feature/new-pipeline-instructions`), `bugfix`, or other meaningful info.
- Add your name/handle in the branch name if needed to avoid confusion.
- If your development relates to an Issue or a Feature Request, add its reference in the branch name.
- Try to stash your changes before submitting a PR.

## How to update the **Instructions**

Useful link: [https://redhat-scholars.github.io/build-course/rhs-build-course/develop.html](https://redhat-scholars.github.io/build-course/rhs-build-course/develop.html)

### Requirements

- Podman or Docker

### Development

- Add/Modify/Delete content in [content/modules/ROOT](content/modules/ROOT).
- Navigation is handled in `nav.adoc`.
- Content pages are in the `pages` folder.
- To build the site, from the root of the repo, run `./content/utilities/lab-build`.
- To serve the site for previewing, from the root of the repo, run `./content/utilities/lab-serve`.
- The site will be visible at [http://localhost:8443/](http://localhost:8443/)
- When finished, you can stop serving the site by running from the root of the repo `./content/utilities/lab-stop`.

## How to update the **Application**

### Requirements

- Python 3.11
- Nodejs > 18
- An existing instance of Hugging Face TGI with a loaded model available at `INFERENCE_SERVER_URL`. This application is based on Mistral-TB Prompt format. You will need to modify this format if you are using a different model.

### Installation

Run `npm install` from the main folder.

If you want to install packages manually:

- In the `frontend` folder, install the node modules with `npm install`.
- In the `backend` folder, create a venv and install packages with the provided Pipfile/Pipfile.lock files.
- In the `backend` folder, create the file `.env` base on the example `.env.example` and enter the configuration for the Inference server.

### Development

From the main folder, launch `npm run dev` or `./start-dev.sh`. This will launch both backend and frontend.

- Frontend is accessible at `http://localhost:9000`
- Backend is accessible at `http://localhost:5000`, with Swagger API doc at `http://localhost:5000/docs`

```bash
#!/bin/bash

# Script to restart all showroom pods - You must be logged in as a cluster admin to run this script

# Get all namespaces
namespaces=$(oc get namespaces -o jsonpath='{.items[*].metadata.name}' \
    | tr ' ' '\n' \
    | grep '^showroom')

# Stop all the pods
for namespace in $namespaces; do
    # Check if the deployment "showroom" exists in the namespace
    if oc -n $namespace get deployment showroom &> /dev/null; then
        # If it exists, restart the rollout
        # oc -n $namespace rollout restart deployment/showroom
        oc -n $namespace scale deploy showroom --replicas=0
    fi
done


# wait for them all to fully stop
# start all the pods
for namespace in $namespaces; do
    # Check if the deployment "showroom" exists in the namespace
    if oc -n $namespace get deployment showroom &> /dev/null; then
        # If it exists, restart the rollout
        # oc -n $namespace rollout restart deployment/showroom
        oc -n $namespace scale deploy showroom --replicas=1
    fi
done


```

## How to graduate code from dev to main

- From `dev`, create a new branch, like `feature/prepare-for-main-merge`.
- Modify the following files to make their relevant content point to `main`:
  - `bootstrap/applicationset/applicationset-bootstrap.yaml`
  - `content/antora.yml`
  - `content/modules/ROOT/pages/05-03-web-app-deploy-application.adoc`
- Make a pull request from this branch to `main`, review and merge

</details>

<details>
  <summary>Links for event environment assignment</summary>

- URL for all labs: Provided during the day
- Login and username: Provided during the day

</details>


# OpenShift AI + Amazon Bedrock Architecture
Let’s begin with an in-depth look at the architecture of our solution.
<!---
 ![Architecture Diagram](architecture-diagram.jpeg "Architecture Diagram")
-->
The entire platform is hosted on AWS, where we harness the combined power of OpenShift AI running on Red Hat OpenShift Service on AWS (ROSA) along with a suite of AWS Bedrock services. This powerful combination enables us to create an advanced, scalable solution designed to meet all of your AI needs.

Red Hat OpenShift Service on AWS (ROSA) is an exceptional, fully managed application platform that has been co-engineered and is jointly supported by both AWS and Red Hat. It provides the perfect foundation for running enterprise-grade applications. When you integrate OpenShift AI on top of ROSA, you can build, train, and deploy AI models seamlessly within a robust, cloud-native environment.

On top of that, AWS offers an array of fully managed AI services like Amazon Bedrock, Amazon Bedrock Knowledge Bases, and many others. These services allow you to focus on driving business value instead of worrying about the complexities of implementing and maintaining infrastructure. With AWS's managed offerings, you're able to accelerate innovation without the overhead of managing an entire AI platform.

For Parasol's solution, we’ve chosen the following combination of services:

- Red Hat OpenShift Service on AWS (ROSA): The foundation for hosting both frontend and backend services.
- OpenShift AI: Providing the AI capabilities on top of ARO.
- SLM Deployment on ROSA to compare results with Amazon Nova
- Amazon Nova: Powering the natural language interface for efficient interaction.
- Amazon Bedrock Knowledge Bases: Serving as a highly capable vector database, with added features beyond just vector storage
- Amazon Aurora PostgreSQL: Supporting our backend database needs, specifically for handling claims.

In this architecture, the frontend and backend services are running on ROSA, with OpenShift AI fully integrated. We leverage Amazon Nova for a natural language processing interface, making it easier for users to interact with the system. For data storage and management, we rely on Amazon Aurora PostgreSQL for the claims database, while Amazon Bedrock Knowledge Bases serves as our vector database, offering enhanced features to improve data retrieval and search functionalities.

By combining these technologies, we create a streamlined, highly efficient solution that allows businesses to focus on innovation and driving real results without the complexity of managing AI platforms.
