FROM maven:3.6.0-jdk-11
WORKDIR /enc-api

COPY . .

RUN mvn compile

ENV TZ="Asia/Kolkata"

CMD ["mvn","exec:java","-Dexec.mainClass=com.getkwikid.enc.App"]
EXPOSE 4366
