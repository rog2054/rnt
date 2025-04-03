pipeline {
    agent any // Runs on any available agent with Docker installed

    environment {
        // Define your Docker registry details
        DOCKER_REGISTRY = 'registry.kranica.com' // e.g., 'myregistry.example.com'
        DOCKER_IMAGE = "${DOCKER_REGISTRY}/rogers-network-tools" // Image name in registry
        DOCKER_CREDENTIALS_ID = 'registry-kranica-com-user' // Jenkins credential ID for registry login
        GITEA_CREDENTIALS_ID = 'gitea-jenkinsuser' // 'jenkins' user within Gitea
    }

    stages {
        stage('Checkout') {
            steps {
                // Pull the code from your Gitea repo
                git url: 'https://gitea.kranica.com/dev1/bgp-route-tester.git', 
                branch: 'main',
                credentialsId: "${GITEA_CREDENTIALS_ID}"
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    // Build the Docker image with a tag based on the build number
                    def imageTag = "${env.BUILD_NUMBER}"
                    docker.build("${DOCKER_IMAGE}:${imageTag}")
                }
            }
        }

        stage('Push to Docker Registry') {
            steps {
                script {
                    // Log in to the Docker registry and push the image
                    docker.withRegistry("https://${DOCKER_REGISTRY}", DOCKER_CREDENTIALS_ID) {
                        def imageTag = "${env.BUILD_NUMBER}"
                        def dockerImage = docker.image("${DOCKER_IMAGE}:${imageTag}")
                        dockerImage.push() // Push the specific tag
                        dockerImage.push('latest') // Also tag and push as 'latest'
                    }
                }
            }
        }

        stage('Run Docker Container') {
            steps {
                script {
                    // Stop and remove any existing container with the same name (optional)
                    sh 'docker stop flask-app-container || true'
                    sh 'docker rm flask-app-container || true'

                    // Run the new container from the latest image
                    sh "docker run -d --name flask-app-container -p 5000:5000 ${DOCKER_IMAGE}:latest"
                }
            }
        }
    }

    post {
        always {
            // Clean up dangling images (optional)
            sh 'docker image prune -f'
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed.'
        }
    }
}