const merge = require('lodash.merge');

const dev = {
    app: {
        port: 2525,
	baseURL: '/',
        session:  {
            name: 'sid',
            secret: 'mysecret',
            requireHTTPS: false,
            
            // 0 = infinite
            maxAge: 1000*60*60*24
        },
        proxy: {
            trust: true,
            ips: []
        }
    },
    oauth2: {
        'google' : {
            name: 'Google',
            clientID: '',
            clientSecret: '',
            callbackURL: '/auth/google/callback'
        },
        'github': {
            name: 'GitHub',
            provider: 'github',
            clientID: '',
            clientSecret: '',
            callbackURL: '/auth/github/callback'
        }
    }
}

// Site specific options go in the config-app.js file
const appSecret = require('./config-app.js')
merged = merge( dev, appSecret);

const config = {
    dev
}


module.exports = merged
