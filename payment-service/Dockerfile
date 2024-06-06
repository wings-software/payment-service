From tomcat:8.0.51-jre8-alpine



RUN apk update && apk add --no-cache nmap && \
    echo @edge http://nl.alpinelinux.org/alpine/edge/community >> /etc/apk/repositories && \
    echo @edge http://nl.alpinelinux.org/alpine/edge/main >> /etc/apk/repositories && \
    apk update && \
    apk add --no-cache \
      chromium \
      harfbuzz \
      "freetype>2.8" \
      ttf-freefont \
      nss


 
COPY ./payment-service/target/*.jar payment-service.jar

EXPOSE 8080

CMD ["java","-jar","payment-service.jar"]                              
