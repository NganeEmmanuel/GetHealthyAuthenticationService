# Use OpenJDK 21 as the base image
FROM openjdk:21-jdk

# Set the working directory inside the container
WORKDIR /app

# Copy the JAR file to the container
COPY target/AuthenticationService-0.0.1-SNAPSHOT.jar /app/authenticationService.jar

# Expose the port that the service will run on
EXPOSE 8082

# Command to run the application
ENTRYPOINT ["java", "-jar", "/app/authenticationService.jar"]
