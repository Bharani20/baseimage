var config = {};

config.cdip = {};

config.cdip.PORT =
    process.env.PORT || 3000;

config.cdip.CHALLENGE = process.env.CHALLENGE || `Server Challenge`;

config.cdip.POST_METHOD = process.env.POST_METHOD || `POST`;

config.cdip.secretKey = process.env.secretKey || '5cec035537bf20697cec520fc0d9f8d7c874d414fb7b49b9a75a27d890943c00';

config.cdip.JAVA_URL =
    process.env.JAVA_URL || "https://dj1.aramco.com.sa";

//  "https://pj1.aramco.com.sa";  "https://dj1.aramco.com.sa"; 

config.cdip.ORACLE_URL =
    process.env.ORACLE_URL || "http://java-oracle-service-master:8080";

// "http://java-oracle-service:8080"; "http://java-oracle-service-master:8080";

config.cdip.JWTSESSION = process.env.JWTSESSION || `2h`;

config.cdip.SPLUNKIP = process.env.SPLUNKIP || '10.1.252.77';
config.cdip.SPLUNKPORT = process.env.SPLUNKPORT || '10753'

module.exports = config;