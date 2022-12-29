FROM tomcat:jre8-openjdk-slim-buster
 

RUN apt-get update
RUN apt-get install -y wget
      
RUN wget -qO- https://get.et.harness.io/releases/latest/nix/harness-et-agent.tar.gz | tar -xz

 
COPY ./payment-service/target/*.jar payment-service.jar

EXPOSE 8080

CMD ["java","-jar","-agentpath:./harness/lib/libETAgent.so","payment-service.jar"]  
