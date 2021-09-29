
const {v4: UUID} = require('uuid')
const {default: shortid } = require('short-unique-id')
const ip = require('ip')
const qrcode = require('qrcode')

const express = require('express')
const session = require('express-session')
const sharedSession = require("express-socket.io-session")

const passport = require('passport')
const { request, response } = require('express')

// Load the application configuration and authentication providers
const config = require('./config-defaults.js')
const authProviders = require('./auth.js')

const app = express();
const server = require('http').createServer(app)
const io = require('socket.io')(server)

const sessionStore = new session.MemoryStore();
const expressSession = session({
    name: config.app.session.name,
    store: sessionStore,
    secret: config.app.session.secret,
    resave: true,
    saveUninitialized: true,
    cookie: {
        path: '/',
        httpOnly: true,
        secure: config.app.session.requireHTTPS,
        maxAge: config.app.session.maxAge
    }
})

const shortUUID = new shortid();
const hostIP = ip.address();
const PORT = 2525;

app.use(express.json())
app.use(express.urlencoded({
    extended: true
}))
app.use(expressSession)
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static('static'))

app.set('trust proxy', config.app.proxy.trust, config.app.proxy.ips);
app.set('view engine', 'pug')

io.use(sharedSession(expressSession,{
    autoSave: true
}))


const baseURL = config.app.baseURL;
let connections = []
let requestQueues = []
let loggedInUsers = {}

function wildcardMatch( pattern, str ){
    let pSpot = 0;
    let sSpot = 0;

    let sWild = -1;
    let pWild = -1;
    while( sSpot < str.length ){
        if( pattern[pSpot] === str[sSpot] ) {
            pSpot += 1;
            sSpot += 1;
        }
        else if( pSpot < pattern.length && pattern[pSpot] === '*' ) {
            sWild = sSpot;
            pWild = pSpot;

            pSpot += 1;
        }
        else if( pWild !== -1 ) {
            pSpot = pWild + 1;
            sSpot = sWild + 1;
            sWild += 1;
        }
        else{
            return false;
        }
    }

    while( pSpot < pattern.length && pattern[pSpot] === '*' ){
        pSpot += 1;
    }
    if( pSpot == pattern.length ){
        return true;
    }

    return false;
}

app.get('/', function(req, res){
    
})


// Setup the OAuth providers
for( const provider in authProviders ){
    app.get(`/auth/${provider}`, passport.authenticate(provider, { scope: ['email', 'profile'] }))
    app.get(authProviders[provider].callbackURL, 
      passport.authenticate(provider, { failureRedirect: '/login' }),
      function(req, res) {
    
        if( !(req.sessionID in loggedInUsers)){
            loggedInUsers[req.sessionID] = {
                logins: []
            }
        }
 
        let login = authProviders[provider].mapFields(req.user);
        login.providerLabel = authProviders[provider].name
        login.provider = provider

        loggedInUsers[req.sessionID].logins.push(login);
        res.redirect(req.session.lastUrl)
    });
}

passport.serializeUser(function(user, done) {
    done(null, user);
});
  
passport.deserializeUser(function(user, done) {
    done(null, user);
});

// Capture the favicon.ico so it doesn't trigger
app.get('/favicon.ico', function(req,res) {
    res.status(204);
})

app.get('/:id', function(req,res){

    let fullUrl = `${req.protocol}://${req.get('host')}`
    req.session.lastUrl = `${baseURL}/${req.params.id}`;
    req.session.lastKnownIP = req.ip;

    if( !(req.params.id in requestQueues) ){
        req.session.lastUrl = `${baseURL}/${req.params.id}/admin`;

        let servicePermissions = {
            admin:{},
            access:{},
            blocked:{}
        };
        for( const provider in authProviders){
            for(const acc in servicePermissions ){
                servicePermissions[acc][provider] = {};
            }
        }

        requestQueues[req.params.id] = {
            queueID: req.params.id,
            connections: [],
            adminKeys: [],
            requesters: [],
            requestersPrivateData: [],
            blocked:[],
            servicePermissions,
            config: {
                done: false,
                private: true,
                adminPassword: '',
                accessPassword: '',
                port: PORT
            },
            polling: {
                activePoll: '',
                polls: []
            }
        }

        logins = []
        if( req.sessionID in loggedInUsers) {
            logins = loggedInUsers[req.sessionID].logins

            // Add logged in identities to the admin permissions automatically
            for( let login of logins ){
                requestQueues[req.params.id].servicePermissions['admin'][login.provider][login.username] = true;
            }

        }

        let token = UUID();
        requestQueues[req.params.id].adminKeys[token] = true;
        res.render('admin', {
	    baseURL, 
            path: fullUrl,
            queueID: req.params.id,
            config: requestQueues[req.params.id].config,
            permissions: {
                admin: true,
                logins
            },
            token, 
            blocked: requestQueues[req.params.id].blocked,
            servicePermissions: requestQueues[req.params.id].servicePermissions,
            authProviders
        })
    }
    else{
    
        let permissions = {
            access : false,
            admin : false,
            logins: []
        }

        if( req.sessionID in loggedInUsers) {
            permissions.logins = loggedInUsers[req.sessionID].logins

            // Admin permissions
            for( let connection of permissions.logins){
                let provider = connection.provider;
                for( let p in requestQueues[req.params.id].servicePermissions['admin'][provider]){
                    if( wildcardMatch(p, connection.username)){
                        permissions.admin = true;
                        break;
                    }
                }
            }

            for( let connection of permissions.logins ) {
                let provider = connection.provider;
                for( let p in requestQueues[req.params.id].servicePermissions['access'][provider]){
                    if( wildcardMatch(p, connection.username)){
                    permissions.access = true;
                    break;
                    }
                }                
            }
        }
        if( requestQueues[req.params.id].config.adminPassword.length > 0 
            && req.query.access === requestQueues[req.params.id].config.adminPassword){
            permissions.admin = true;
        }

        if(permissions.admin 
            || (requestQueues[req.params.id].config.accessPassword === '' && !requestQueues[req.params.id].config.private) 
            || req.query.access === requestQueues[req.params.id].config.accessPassword){
            permissions.access = true;
        }

        qrcode.toDataURL(fullUrl+`${baseURL}/${req.params.id}`, {
            errorCorrectionLevel: 'L',
            version: 3

        },function(err, url){
            fullUrl += `/${baseURL}/${req.params.id}`
            res.render('qr',{
                queueID: req.params.id,
                config: requestQueues[req.params.id].config,
                requesters: requestQueues[req.params.id].requesters,
                permissions, 
                qrcode: url,
                URL: fullUrl,
		baseURL,
                authProviders
            })
        })
    }
})

app.post('/logout', function(req, res){
    let response = {
        status: false,
        message: 'Not Logged In'
    }

    if(req.sessionID in loggedInUsers){
        let [provider, username] = req.body.identity.split(':');

        for( let i = 0; i < loggedInUsers[req.sessionID].logins.length; i++ ) {
            let login = loggedInUsers[req.sessionID].logins[i]
            if( login.provider === provider && login.username === username ){
                loggedInUsers[req.sessionID].logins.splice(i,1);
                i--;

                response.status = true;
                response.message = `${username} from ${provider} logged out`;
            }
        }
    }
    res.send(JSON.stringify(response))
})


app.get('/:id/admin', function(req, res){
    let qid = req.params.id;
    req.session.lastUrl = `${baseURL}/${qid}/admin`;

    if( !(qid in requestQueues) ){
        res.send("That queue does not exist");
        return;
    }
   
    let fullUrl = `${req.protocol}://${req.get('host')}`

    let permissions =  {
        admin: false,
        logins: []
    }

    if( req.sessionID in loggedInUsers) {
        permissions.logins = loggedInUsers[req.sessionID].logins
        for( let connection of permissions.logins){
            let provider = connection.provider;
            for( let p in requestQueues[req.params.id].servicePermissions['admin'][provider]){
                if( wildcardMatch(p, connection.username)){
                    permissions.admin = true;
                    break;
                }
            }
        }
    }

    res.render('admin', {
        permissions, 
	baseURL,
        path: fullUrl,
        queueID: req.params.id,
        config: requestQueues[req.params.id].config,
        blocked: requestQueues[req.params.id].blocked,
        servicePermissions: requestQueues[req.params.id].servicePermissions,
        authProviders
    })
})

app.post('/:id/admin', function(req, res){
    let qid = req.params.id;
    let token = req.body.token || '';
  
    let response = {
        status: false,
        message: 'Admin Code Required',
        token
    }

    if( !(qid in requestQueues) ){
        response.message = 'That queue does not exist';
        res.send(JSON.stringify(response));
        return;
    }

    let permissions = {
        admin : false,
        logins: []
    }

    if( req.body.access === requestQueues[qid].config.adminPassword ||
        req.body.token in requestQueues[qid].adminKeys
        ){
        delete requestQueues[qid].adminKeys[req.body.token];

        response.token = UUID();
        requestQueues[qid].adminKeys[response.token] = true;
        permissions.admin = true;
    }
    
    if( permissions.admin ) {
        if( typeof req.body.private !== 'undefined' ){
            requestQueues[qid].config.private = req.body.private;
            response.status = true;
        }

        if( typeof req.body.action !== 'undefined' ) {
            if( req.body.action === 'deleteaccess' ){
                let [provider,role,username] = req.body.access.split(':');
                delete requestQueues[qid].servicePermissions[role][provider][username];
                response.status = true;
            }
            // Add authenticated login permissions (admin, access, blocked)
            // Default is to reject
            else if( req.body.service !== '') {
                let sp = requestQueues[qid].servicePermissions;
                if( req.body.action in sp && req.body.service in sp[req.body.action] ){
                    if( req.body.access && req.body.action){
                        requestQueues[qid].servicePermissions[req.body.action][req.body.service][req.body.access] = true;
                        response.status = true;
                    }
                }
            } 
            // Unauthenticated admin
            else if(req.body.action == 'admin' ){
                requestQueues[qid].config.adminPassword = req.body.access;
                response.status = true;
            }
            // Unauthenticated access
            else if(req.body.action === 'access' ){
                requestQueues[qid].config.accessPassword = req.body.access;
                response.status = true;
            }
            else if(req.body.action === 'deleteblock' ) {
                let ip = req.body.ip;
                delete requestQueues[req.params.id].blocked[ip]
                response.status = true;
            }
        }
        response.message = 'Settings successfully changed.'
    }
    if( req.body.mode === 'html' ){
        let fullUrl = `${req.protocol}://${req.get('host')}`
        res.render('admin', {
	    baseURL, 
            path: fullUrl,
            queueID: req.params.id,
            config: requestQueues[req.params.id].config,
            permissions, 
            token: response.token,
            blocked: requestQueues[req.params.id].blocked,
            servicePermissions: requestQueues[req.params.id].servicePermissions,
            authProviders
        })
    }
    else {
        res.send(JSON.stringify(response))
    }
})


io.on('connection', function(socket){

    let clientIP = socket.handshake.session.lastKnownIP;
    let qid = null;
    let enQd = false;
    let adminMode = false;
    socket.on('qr:queue:join', function(id, password, ackfn){
        let response = {
            status : false,
            admin: false,
            message: '',
            loggedIn: false,
            data: []
        }


        // Authenticated login permission check
        if( socket.handshake.session.passport ){
            response.loggedIn = true;

            if( id in requestQueues && socket.handshake.sessionID in loggedInUsers ) {
                
                permissions = loggedInUsers[socket.handshake.sessionID].logins
                // Check OAuth for admin permissions
                for( let connection of permissions){
                    let provider = connection.provider;
                    for( let p in requestQueues[id].servicePermissions['admin'][provider]){
                        if( wildcardMatch(p, connection.username)){
                            response.status = true;
                            response.admin = true;
                            response.message = shortUUID.randomUUID(8);
                            requestQueues[id].adminKeys[socket.id] = response.message;
                            adminMode = true;
                            break;
                        }
                    }
                }

                for( let connection of permissions ) {
                    let provider = connection.provider;
                    for( let p in requestQueues[id].servicePermissions['access'][provider]){
                        if( wildcardMatch(p, connection.username)){
                            response.status = true;
                            response.message = 'access';
                            break;
                        }
                    }                
                }
            }
        }

        if( id in requestQueues && response.status === false){

            response.status = true;
            if( requestQueues[id].config.adminPassword.length > 0 
                && password === requestQueues[id].config.adminPassword ){ 
                response.status = true;
                response.admin = true;
                response.message = shortUUID.randomUUID(8);
                requestQueues[id].adminKeys[socket.id] = response.message;
                
                adminMode = true;
            }
            else if((requestQueues[id].config.accessPassword === '' && !requestQueues[id].config.private) || 
                    (requestQueues[id].config.accessPassword.length > 0 && password === requestQueues[id].config.accessPassword) ){
                response.message = 'access';
            }
            else {
                delete requestQueues[id].connections[socket.id];
                delete requestQueues[id].adminKeys[socket];

                if( password === ''  ){
                    response.message = "Queue requires access password.";
                }
                else {
                    response.message = "Incorrect Password";
                }
                response.status = false;
            }
        }
        else {
            response.message = 'Queue does not exist.'    
        }

	

        if( response.status === true ){
            qid = id;
            requestQueues[id].connections[socket.id] = socket;
            response.data = requestQueues[id].requesters;

	    // Don't allow entries from IPs that have been blocked
            for( let i = 0; i < requestQueues[qid].blocked.length; i++ ) {
                let blocked = requestQueues[qid].blocked[i];
                let block = false;

                if( blocked.timeUntil < Date.now() ) {
                    requestQueues[qid].blocked.splice(i,1);
                    i--;
                    continue;
                }

                // By IP
                if( blocked.ip === clientIP )
                {
                    block = true;
                }

                // By ID
                let loggedInIDs = loggedInUsers[sessionID].logins;
                for( let loggedInID of loggedInIDs ) {
                    for( let id of blocked.ids ) {
                        if( id.username === loggedInID.username && id.provider === loggedInID.provider ){
                            block = true;
                        }
                    }    
                }
            
                // Blocked
                if( block === true ){
                    let blockMsg = {
                        timeUntil: blocked.timeUntil,
                        reason: blocked.reason,
                    }
                    socket.emit('qr:admin:block', blockMsg );
                    response.message = 'Client blocked'
                    ackfn(response);
                    return;
                }
            }

            // Check for active polling
            if( requestQueues[id].polling.activePoll ){
                let poll = requestQueues[id].polling.polls[requestQueues[id].polling.activePoll];
                let creator = poll.creator;
                delete poll.creator;
                io.emit('qr:poll:start', poll );
                poll.creator = creator;
            }
        }

        ackfn(response);
    })

    socket.on('disconnect', function(){
        if( !(qid in requestQueues) ){ return;}

        delete requestQueues[qid].connections[socket.id];
        delete requestQueues[qid].adminKeys[socket.id];
    })

    socket.on('qr:admin:userinfo', function(uuid, ackfn) {
        if(!adminMode ){
            return;
        }

        let response = {
            ids: [],
            ip: ''
        }

        for( let spot = 0; spot < requestQueues[qid].requesters.length; spot++){
            let conn = requestQueues[qid].requesters[spot];
            if( conn.uuid === uuid ){
                response.ip = requestQueues[qid].requestersPrivateData[spot].ip;
                
                if(requestQueues[qid].requestersPrivateData[spot].sessionID in  loggedInUsers ) {
                    response.ids = loggedInUsers[requestQueues[qid].requestersPrivateData[spot].sessionID].logins;        
                }
            }
        }

        ackfn(response);
    })

    socket.on('qr:admin:block', function(uuid, options){  
        if(!adminMode){
            return;
        }
        let reason = options.reason || '';
        let banID = options.banID;
        let banIP = options.banIP;


        let milliseconds = parseInt(options.duration)*60*1000;
        let timeUntil = Date.now() + milliseconds;

        let blocked = {
            uuid,
            timeUntil,
            reason, 
            ids: [],
            ip: ''
        }

        // Block by IP and/or ID
        for( let spot = 0; spot < requestQueues[qid].requesters.length; spot++){
            let conn = requestQueues[qid].requesters[spot];
            if( conn.uuid === uuid ){
                
                if( banIP === true ) {
                    blocked.ip = blockedIP = requestQueues[qid].requestersPrivateData[spot].ip;
                }

                if( banID === true && requestQueues[qid].requestersPrivateData[spot].sessionID in loggedInUsers ){  
                    blocked.ids = loggedInUsers[requestQueues[qid].requestersPrivateData[spot].sessionID].logins;
                }

                sessionID = requestQueues[qid].requestersPrivateData[spot].sessionID;
                // Add to the blocked list
                requestQueues[qid].blocked.push(blocked);         
            }
        }

        // Remove all entries from this banned user   
        let notifiedSockets = []
        for( let s = 0; s < requestQueues[qid].requesters.length; s++ ){
            let del = requestQueues[qid].requestersPrivateData[s].ip === blocked.ip;

            if( requestQueues[qid].requestersPrivateData[s].sessionID in loggedInUsers){
                for( let loggedIn of loggedInUsers[requestQueues[qid].requestersPrivateData[s].sessionID].logins){
                    for( let blockedLogin of blocked.ids ){
                        if( blockedLogin.username === loggedIn.username && blockedLogin.provider === loggedIn.provider ) {
                            del = true;
                            break;
                        }
                    }

                    if(del === true ){
                        break;
                    }
                }
            }
            
            if( del === true ){
                let notifySocket = requestQueues[qid].requestersPrivateData[s].socket

                deleteSpot(requestQueues[qid].requesters[s].uuid);
                s--;

                if( !(notifySocket.id in notifiedSockets) ){
                    notifiedSockets[notifySocket.id] = true;
                    notifySocket.emit('qr:admin:block', {
                        timeUntil,
                        reason
                    } );
    
                }
            }
        }

        


    })

    socket.on('qr:admin:delete',function(uuid){
        deleteSpot(uuid);
    } )

    function deleteSpot(uuid){
        if(!adminMode){
            return;
        }

        for( let spot = 0; spot < requestQueues[qid].requesters.length; spot++ ){
            if( requestQueues[qid].requesters[spot].uuid === uuid ){
                requestQueues[qid].requesters.splice(spot,1);
                requestQueues[qid].requestersPrivateData.splice(spot,1);
                for( let connection in requestQueues[qid].connections ){
                    let conn = requestQueues[qid].connections[connection];
                    conn.emit('qr:admin:delete', uuid);
                }
                break;
            }
        }
    }


    socket.on('qr:admin:move', function(fromUUID, beforeToUUID){
        if( !adminMode ) {
            return;
        }
        
        let toSpot = -1
        let fromSpot = -1
        for( let spot = 0; spot < requestQueues[qid].requesters.length; spot++ ){
            if( requestQueues[qid].requesters[spot].uuid === fromUUID ){
                fromSpot = spot;
            }
            if( requestQueues[qid].requesters[spot].uuid === beforeToUUID ){
                toSpot = spot
            }
        }
        if( toSpot === -1 ){
            toSpot = requestQueues[qid].requesters.length
        }

        // If we're move down, then we need to subtract one
        if( fromSpot < toSpot ){
            toSpot --;
        }

        let removeElement = requestQueues[qid].requesters.splice(fromSpot, 1)[0];
        requestQueues[qid].requesters.splice(toSpot, 0, removeElement );
        
        removeElement = requestQueues[qid].requestersPrivateData.splice(fromSpot, 1)[0];
        requestQueues[qid].requestersPrivateData.splice(toSpot, 0, removeElement );
        for( let connection in requestQueues[qid].connections ){
            let conn = requestQueues[qid].connections[connection]
            conn.emit('qr:admin:move', fromUUID, beforeToUUID)
        }
    })

    socket.on('qr:request:enqueue', function(data, ackfn){   

        let response = {
            status: false,
            message: ''
        }

        if( !(qid in requestQueues) ||
            !(socket.id in requestQueues[qid].connections) ||
            data.name === null || data.name.trim().length === 0 )
        {
            response.message = 'Invalid request';
            ackfn(response);
            return;
        }

        // Grab the session ID for later
        let sessionID = socket.handshake.sessionID;


        // Don't allow entries from IPs that have been blocked
        for( let i = 0; i < requestQueues[qid].blocked.length; i++ ) {
            let blocked = requestQueues[qid].blocked[i];
            let block = false;

            if( blocked.timeUntil < Date.now() ) {
                requestQueues[qid].blocked.splice(i,1);
                i--;
                continue;
            }

            // By IP
            if( blocked.ip === clientIP )
            {
                block = true;
            }

            // By ID
            let loggedInIDs = loggedInUsers[sessionID].logins;
            for( let loggedInID of loggedInIDs ) {
                for( let id of blocked.ids ) {
                    if( id.username === loggedInID.username && id.provider === loggedInID.provider ){
                        block = true;
                    }
                }    
            }
            
            // Blocked
            if( block === true ){
                let blockMsg = {
                    timeUntil: blocked.timeUntil,
                    reason: blocked.reason,
                }
                socket.emit('qr:admin:block', blockMsg );
                response.message = 'Client blocked'
                ackfn(response);
                return;
            }
        }

        // Don't allow two entries from the same IP address
        // TODO: There must be a better way to do this
        for( let req of requestQueues[qid].requesters ){
            if( req.ip === clientIP ){
                response.message = "Client is limited to one request at a time"
                ackfn(status);
                return;
            }
        }
        
        let uuid = UUID();
        let reason = data.reason || '';
        let requester = {
            name: data.name,
            reason,
            uuid
        }

        let requesterPrivateData = {
            ip: clientIP,
            sessionID,
            socket
        }

        if(!enQd){
            requestQueues[qid].requesters.push(requester);
            requestQueues[qid].requestersPrivateData.push(requesterPrivateData)
            for( let connection in requestQueues[qid].connections){
                let conn = requestQueues[qid].connections[connection]
                conn.emit('qr:request:enqueue', uuid, requester)
            }
            enQd = false;

            response.stats = true;
        }
        else {
            socket.emit('infoMessage', 'Already Enqueued')
        }
        ackfn(response);
    })

    socket.on('qr:poll:create', function( data, ackfn ) {
        
        let response = {
            status: false,
            message: ''
        }

        if(!adminMode){
            response.message = 'Administrator privileges required.'
        }
        else {
            response.message = UUID();
            response.status = true;

            // Free Response
            let votes = [];
            if( data.answers.length > 0 ){
                // Use hashmaps to store multiple choice answers
                votes = {};
            }


            let poll = {
                creator: socket.id,
                id: response.message,
                question: data.question,
                answers: data.answers,
                multipleAnswers: data.multipleAnswers,
                votes
            }
            requestQueues[qid].polling.polls[poll.id] = poll;
        }
        ackfn( response );
    })

    socket.on('qr:poll:start', function( data, ackfn) {

        if( !adminMode ){
            response.message = 'Administrator privilege required.'
            ackfn(response)
        }
        else {
            if( qid in requestQueues && data.uuid in requestQueues[qid].polling.polls ){
                let poll = requestQueues[qid].polling.polls[data.uuid];
              
                if( requestQueues[qid].polling.activePoll ) {
                    ackfn({
                        status: false,
                        message: 'A poll is already actively running.',
                        id: poll.id
                    })
                }
                else {

                    requestQueues[qid].polling.activePoll = poll.id;
                    ackfn({
                        status: true,
                        id: poll.id
                    })

                    // Don't send the creator's session ID
                    let creator = poll.creator;
                    delete poll.creator;
                    io.emit('qr:poll:start', poll );
                    poll.creator = creator;   
                }
            }
        }
    })
    socket.on('qr:poll:vote', function( data, ackfn){

        let response ={
            status: true,
            message: ''
        }

        if( qid in requestQueues && data.uuid === requestQueues[qid].polling.activePoll){
            let poll = requestQueues[qid].polling.polls[data.uuid]
            if( typeof data.vote === 'string' ){
                poll.votes.push(data.vote);
            }
            else {
                for( let vote of data.vote ) {
                    if( vote in poll.votes ){
                        poll.votes[vote.toString()] += 1;
                    }
                    else{
                        poll.votes[vote.toString()] = 1;
                    }
                }
            }
            io.to(poll.creator).emit('qr:poll:update', poll.votes);
        }
        else {
            response.status = false;
            response.message = 'This poll is not active'
        }

        ackfn(response)
    })
    socket.on('qr:poll:end', function(data, ackfn){
        if( !adminMode ) {
            ackfn({
                status: false,
                message: 'Administrator privilege required.'
            })
        }
        else {
            let response = {
                status: false,
                message: ''
            }

            if( qid in requestQueues && requestQueues[qid].polling.activePoll === data.uuid ){
                let poll = requestQueues[qid].polling.polls[data.uuid];
              
                if( socket.id !== poll.creator ){
                    response.message = 'Only the poll creator can end a poll'
                }
                else {
                    
                    response.status = true;
                    requestQueues[qid].polling.activePoll = '';

                    // Final update
                    io.to(poll.creator).emit('qr:poll:update', poll.votes);

                    // Don't send the creator's session ID
                    let creator = poll.creator;
                    delete poll.creator;
                    io.emit('qr:poll:end', poll );
                    poll.creator = creator;  
                }

              
            } 
            else {
                response.message = 'Requested poll is not the active poll.'
            } 
            ackfn( response )         
        }
    })
   
})

server.listen(PORT, function(){
    console.log(`Server URL: http://${hostIP}:${PORT}`);
})
