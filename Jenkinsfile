pipeline {
    agent any // Runs on any available agent with Docker installed

    environment {
        // Define your Docker registry details
        DOCKER_REGISTRY = 'registry.kranica.com' // e.g., 'myregistry.example.com'
        DOCKER_IMAGE = "${DOCKER_REGISTRY}/rogers-network-tools" // Image name in registry
        DOCKER_CREDENTIALS_ID = 'registry-kranica-com-user' // Jenkins credential ID for registry login
        GITEA_CREDENTIALS_ID = 'gitea-jenkinsuser' // 'jenkins' user within Gitea
        DOCKER_HUB_IMAGE = "roger00/rogers-network-tools"
        FULL_BUILD = 'true' // false only builds in dev, true builds in dev then pushes to hub also
    }

    stages {
        stage('Checkout') {
            steps {
                // Pull the code from your Gitea repo
                git url: 'https://gitea.kranica.com/dev1/rogers-network-tools.git', 
                branch: 'main',
                credentialsId: "${GITEA_CREDENTIALS_ID}"
                sh 'ls -la' // List files to verify Dockerfile
            }
        }


        stage('Build Docker Image') {
            steps {
                script {
                    def imageTag = "${env.BUILD_NUMBER}"
                    // Write the build number to a version file
                    sh "echo ${imageTag} > version.txt"
                    // Use the stored ENCRYPTION_KEY from Jenkins credentials
                    withCredentials([string(credentialsId: 'rnt-encryption-key', variable: 'ENCRYPTION_KEY')]) {
                        // Build the Docker image, including the version file and ENCRYPTION_KEY
                        docker.build("${DOCKER_IMAGE}:${imageTag}", "--build-arg ENCRYPTION_KEY=${ENCRYPTION_KEY} .")
                    }
                }
            }
        }

        stage('Push to Private Registry') {
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
                    // Stop and remove any existing container with the same name (if it exists)
                    sh 'docker stop flask-app-container || true'
                    sh 'docker rm flask-app-container || true'

                    // Run the new container and capture the container ID
                    def containerId = sh(script: "docker run -d --name flask-app-container -p 5000:5000 ${DOCKER_IMAGE}:latest", returnStdout: true).trim()
                    echo "Started container with ID: ${containerId}"

                    // Wait briefly to ensure the container starts
                    sleep 5

                    // Check if the container is still running
                    def running = sh(script: "docker ps -q -f id=${containerId}", returnStdout: true).trim()
                    if (running) {
                        echo "Container ${containerId} is running."
                    } else {
                        echo "Container ${containerId} is not running. Checking logs..."
                        sh "docker logs ${containerId}"
                        error "Container failed to stay running. See logs above for details."
                    }
                }
            }
        }

        stage('Push to Docker Hub') {
            when {
                allOf {
                    expression {
                        // Only if the dev container ran successfully without terminating itself
                        return currentBuild.resultIsBetterOrEqualTo('SUCCESS')
                    }
                    environment name: 'FULL_BUILD', value: 'true'
                }
            }
            steps {
                script {
                    def imageTag = "${env.BUILD_NUMBER}"
                    // Tag the private registry image for Docker Hub using docker tag command
                    sh "docker tag ${DOCKER_IMAGE}:${imageTag} ${DOCKER_HUB_IMAGE}:${imageTag}"
                    // Log in to Docker Hub and push the tagged image
                    docker.withRegistry('https://index.docker.io/v1/', 'docker-hub-credentials') {
                        def dockerImageForHub = docker.image("${DOCKER_HUB_IMAGE}:${imageTag}")
                        dockerImageForHub.push('latest') // Push as 'latest' to Docker Hub
                    }
                }
            }
        }
        
    }

    post {
        always {
            // Clean up dangling images (optional)
            sh 'docker image prune -f'

            script {
                // Get build status
                def status = currentBuild.currentResult
                def buildType = env.FULL_BUILD == 'true' ? 'dev+hub' : 'dev-only'
                def message = "🔔 Jenkins Build: *${env.JOB_NAME}* #${env.BUILD_NUMBER} has *${status}* (${buildType}).\n" +
                            "🔗 [View Build](${env.BUILD_URL})"

                // Use withCredentials to securely fetch bot token and chat ID
                withCredentials([
                    string(credentialsId: 'telegram-bot-token', variable: 'TOKEN'),
                    string(credentialsId: 'rr-telegram-id', variable: 'CHAT_ID')
                ]) {
                    // Build the Telegram URL
                    def url = "https://api.telegram.org/bot${TOKEN}/sendMessage"

                    // Send the message using curl with proper escaping
                    sh """
                        curl -s -X POST '${url}' \
                            -d chat_id='${CHAT_ID}' \
                            -d parse_mode=Markdown \
                            --data-urlencode 'text=${message}'
                    """
                }
            }
        }

        success {
            echo 'Pipeline completed successfully!'
        }

        failure {
            echo 'Pipeline failed.'
        }
    }

}

