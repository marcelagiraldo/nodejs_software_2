const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const {API_VERSION} = require('./constants')
const app = express()
/* cargar rutas */
const authRoutes = require("./src/routes/auth")
/* const userRoutes = require("./src/routes/user") */
/* Trabajr con la extension client-rest */
app.use(bodyParser.json())
/* Pruebas de request usando postman */
app.use(bodyParser.urlencoded({ extended : true}))
/* Evitar bloqueos en el navegador cuando se trabaje con back y front a la vez */
app.use(cors())
console.log(`api/${API_VERSION}/`);
app.use(`/api/${API_VERSION}/auth`, authRoutes);
/* app.use(`/api/${API_VERSION}`, userRoutes); */
module.exports = app;

    