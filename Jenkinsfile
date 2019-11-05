@Library('jenkins-joylib@v1.0.2') _

pipeline {

    agent none

    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timestamps()
    }

    stages {
        stage('top') {
            parallel {
                stage('v0.10.48-zone') {
                    agent {
                        label joyCommonLabels(image_ver: '15.4.1')
                    }
                    tools {
                        nodejs 'sdcnode-v0.10.48-zone'
                    }
                    stages {
                        stage('check') {
                            steps{
                                sh('make check')
                            }
                        }
                        stage('test') {
                            steps{
                                sh('make test')
                            }
                        }
                    }
                }

                stage('v4-zone64') {
                    agent {
                        label joyCommonLabels(image_ver: '15.4.1')
                    }
                    tools {
                        nodejs 'sdcnode-v4-zone64'
                    }
                    stages {
                        stage('check') {
                            steps{
                                sh('make check')
                            }
                        }
                        stage('test') {
                            steps{
                                sh('make test')
                            }
                        }
                    }
                }

                stage('v6-zone64') {
                    agent {
                        label joyCommonLabels(image_ver: '18.4.0')
                    }
                    tools {
                        nodejs 'sdcnode-v6-zone64'
                    }
                    stages {
                        stage('check') {
                            steps{
                                sh('make check')
                            }
                        }
                        stage('test') {
                            steps{
                                sh('make test')
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            joyMattermostNotification()
        }
    }
}
