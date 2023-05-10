const bcrypt = require("bcryptjs");
const User = require("../models/user");
const jwt = require("../utils/jwt");
const axios = require("axios")

const register = async(req,res) =>{
    const {firstname, lastname , email, password,departamento,municipio} = req.body;
    if (!email) res.status(400).send({msg:"El email es requerido"})
    if (!password) res.status(400).send({msg:"La contraseña es requerida"})
    try{
        /* Se consume la api */
        const response = await axios.get("https://www.datos.gov.co/resource/xdk5-pm3f.json")
        const data = response.data
        /* Se verifica que los datos ingresados existan en la API */
        const dpto = data.find(item => item.departamento === departamento)
        const muni = data.find(item => item.municipio === municipio)

        if (!dpto) res.status(400).send({msg:"El departamento no existe en la API"})
        if (!muni) res.status(400).send({msg:"El municipio no existe en la API"})

        const salt = bcrypt.genSaltSync(10);
        const hashPassword = bcrypt.hashSync(password,salt);
        /* Creamos el usuario */
        const user = new User({
            firstname,lastname,email:email.toLowerCase(),role:"user",active:false,password: hashPassword,departamento,municipio
        });

        const userStorage = await user.save();
        res.status(201).send(userStorage);
    }catch(error){
        res.status(400).send({msg:"Error al crear el usuario",error});
        console.error(error);
    }
};

const login = async(req,res)=>{
    const {email,password} = req.body;
    try{
        if(!email || !password){
            throw new Error("El email y la contraseña son obligatorios")
        }
        const emailLowerCase = email.toLowerCase();
        const userStore = await User.findOne({email:emailLowerCase}).exec();
        if(!userStore){
            throw new Error("El usuario no existe");
        }
        const check = await bcrypt.compare(password,userStore.password);
        if(!check){
            throw new Error("Contraseña incorrecta")
        }
        if(!userStore.active){
            throw new Error("Usuario no autorizado o no activo")
        }
        res.status(200).send({
            access: jwt.createAccessToken(userStore),
            refresh: jwt.createAccessToken(userStore)
        })
    }catch (error){
        res.status(400).send({msg:error.message})
    }
}

function refreshAccessToken(req,res){
    const {token} =req.body;
    if (!token) res.status(400).send({msg:"Token requerido"});
    const {user_id} = jwt.decoded(token);
    User.findOne({_id:user_id},(error,userStorage)=>{
        if (error){
            res.status(500).send({msg:"Error del servidor"});
        }else{
            res.status(200).send({accessToken:jwt.createAccessToken(userStorage)});
        }
    })
}

module.exports = {register,login,refreshAccessToken}
