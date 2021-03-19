const crypto = require( 'crypto' );
const { inspect } = require( 'util' );
const { send, json } = require( 'micro' );
const {
	router,
	options,
	post,
	get,
} = require( 'micro-fork' );

const KMSKey = Buffer.from( 'w+YQ0eVUHNzQ2zp/u8Ip1aRsaJQ2sgWzAS5umnXA7JA=', 'base64' );
const iv = Buffer.from('axYxUkFIAe/RMVze4Wkcig==', 'base64');
const KMSAlg = 'aes-256-cbc'

const storage = {
	links: new Map(),
	auth: {},
	tokens: {},
	users: {
		list( filter ) {
			return Object.values( storage.users )
				.filter( value => typeof value !== 'function' )
				.filter( ( { Attributes } ) => {
					if ( ! filter ) {
						return true;
					}

					const object = Attributes.reduce( ( result, { Name, Value } ) => Object.assign( result, { [Name]: Value } ), {} );
					try {
						return new Function( 'object', `with(object) { return ${filter.replace( / =+ /g, ' === ' )}; }` )( object );
					} catch ( error ) {
						return false;
					}
				} );
		},
		add( User ) {
			const userUUID = User.Attributes.find( ( { Name } ) => Name === 'sub' ).Value;
			storage.users[userUUID] = User;
			storage.links.set( User, [] );
		},
		get( name ) {
			if ( storage.users[name] ) {
				return storage.users[name]
			}

			return this.list().find( ( { Username, Attributes } ) => Username === name ||
				Attributes.some( ( { Value } ) => Value === name ),
			);
		},
		del( name ) {
			const user = this.get( name );
			if ( ! user ) {
				return;
			}

			storage.links.get( user ).forEach( action => action() );

			const sub = user.Attributes.find( ( { Name } ) => Name === 'sub' ).Value;
			delete storage.users[sub];
		},
		auth( username, password ) {
			return storage.auth[`${username}:${password}`];
		},
	},
};

storage.users.add( {
	Username: '0c4c4117-a452-4c5d-bf0c-c12abcaa20e2',
	Attributes: [
		{
			Name: 'sub',
			Value: '0c4c4117-a452-4c5d-bf0c-c12abcaa20e2',
		},
		{
			Name: 'zoneinfo',
			Value: 'Unspecified',
		},
		{
			Name: 'email_verified',
			Value: 'true',
		},
		{
			Name: 'profile',
			Value: '5ddd4c860bee5f0011e645e8',
		},
		{
			Name: 'name',
			Value: 'vladimir.bulyga@legatics.com',
		},
		{
			Name: 'email',
			Value: 'vladimir.bulyga@legatics.com',
		},
	],
	UserCreateDate: 1582030568.05,
	UserLastModifiedDate: 1588953614.173,
	Enabled: true,
	UserStatus: 'CONFIRMED',
	PreferredMfaSetting: 'SOFTWARE_TOKEN_MFA',
	UserMFASettingList: [
		'SOFTWARE_TOKEN_MFA',
	],
} );

storage.auth['vladimir.bulyga@legatics.com:Qwerty123!'] = storage.users.get( '0c4c4117-a452-4c5d-bf0c-c12abcaa20e2' );

const uuid = placeholder =>
	placeholder
		? ( placeholder ^ ( ( Math.random() * 16 ) >> ( placeholder / 4 ) ) ).toString( 16 )
		: ( [ 1e7 ] + -1e3 + -4e3 + -8e3 + -1e11 ).replace( /[018]/g, uuid );

const setHeaders = ( req, res, headers = {} ) => {
	res.setHeader( 'access-control-allow-origin', '*' );
	if ( req.headers['access-control-request-headers'] ) {
		res.setHeader( 'access-control-allow-headers', req.headers['access-control-request-headers'] );
	}
	res.setHeader( 'access-control-expose-headers', 'x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date' );
	res.setHeader( 'access-control-allow-methods', req.headers['access-control-allow-methods'] || 'GET, PUT, POST, DELETE, HEAD, OPTIONS' );
	res.setHeader( 'access-control-max-age', '172800' );
	res.setHeader( 'date', new Date().toUTCString() );
	res.setHeader( 'x-amzn-requestid', uuid() );
	Object.entries( headers, ( [ key, value ] ) => {
		res.setHeader( key, value );
	} );
};

const renameProp = ( prev, next, object = {} ) => ( {
	...object,
	[next]: object[prev],
	[prev]: undefined,
} );

module.exports = router()(
	get( '/', ( req, res ) => send( res, 200, { message: 'Service is running' } ) ),
	options( '/', ( req, res ) => {
		setHeaders( req, res );
		send( res, 200 );
	} ),
	post( '/', async ( req, res ) => {
		const body = await json( req );
		console.log( req.headers['x-amz-target'], inspect( body, { depth: 12 } ) );

		setHeaders( req, res, {
			'content-type': 'application/x-amz-json-1.1',
		} );

		// Get existing ID.
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityService.GetCredentialsForIdentity' ) {
			const expiration = new Date();
			expiration.setTime( expiration.getTime() + ( 60 * 60 * 1000 ) );
			send( res, 200, {
				Credentials: {
					AccessKeyId: 'not-needed',
					Expiration: expiration.toISOString(),
					SecretKey: 'not-needed',
					SessionToken: 'not-needed',
				},
				IdentityId: body.IdentityId,
			} );
			return;
		}

		// Get new ID.
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityService.GetId' ) {
			send( res, 200, {
				IdentityId: `us-east-1:${uuid()}`,
			} );
			return;
		}

		// List Users
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.ListUsers' ) {
			send( res, 200, {
				Users: storage.users.list( body.Filter ),
			} );
			return;
		}

		// Admin Delete User
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminDeleteUser' ) {
			storage.users.del( body.Username );
			send( res, 200 );
			return;
		}

		// Admin Update User Attributes
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminUpdateUserAttributes' ) {
			const User = storage.users.get( body.Username );
			if ( ! User ) {
				send( res, 404 );
				return
			}

			for ( const { Name, Value } of body.UserAttributes ) {
				const userAttribute = User.Attributes.find( ( { Name: _name } ) => _name === Name );
				if ( typeof userAttribute === 'undefined' ) {
					User.Attributes.push( {
						Name,
						Value,
					} );
					continue;
				}

				userAttribute.Value = Value;
			}

			send( res, 200, { User } );
			return;
		}

		// Admin Create User
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminCreateUser' ) {
			const userUUID = uuid();
			const addAttribute = ( Name, defaultValue ) => {
				let Value = ( body.UserAttributes || [] ).filter( ( { Name: _name } ) => _name === Name ).map( ( { Value } ) => Value )[0];
				if ( ! defaultValue && ! Value ) {
					return [];
				}

				if ( ! Value ) {
					Value = defaultValue;
				}

				return [ {
					Name,
					Value,
				} ];
			};

			const User = {
				'Username': userUUID,
				'Attributes': [
					{
						'Name': 'sub',
						'Value': userUUID,
					},
					...addAttribute( 'zoneinfo', 'Unspecified' ),
					...addAttribute( 'email_verified', 'Unspecified' ),
					...addAttribute( 'profile' ),
					...addAttribute( 'name', body.Username ),
					...addAttribute( 'email', body.Username ),
				],
				'UserCreateDate': new Date().getTime() / 1000,
				'UserLastModifiedDate': new Date().getTime() / 1000,
				'Enabled': true,
				'UserStatus': 'CONFIRMED',
				'PreferredMfaSetting': 'SOFTWARE_TOKEN_MFA',
				'UserMFASettingList': [
					'SOFTWARE_TOKEN_MFA',
				],
			};

			storage.users.add( User );

			send( res, 200, { User } );
			return
		}

		// Admin Initiate Auth
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminInitiateAuth' ) {
			const token = uuid();
			const User = storage.users.auth( body.AuthParameters.USERNAME, body.AuthParameters.PASSWORD );
			if ( ! User ) {
				send( res, 401 );
				return;
			}

			storage.tokens[token] = User;
			storage.links.get( User ).push( () => delete storage.tokens[token] );

			send( res, 200, {
				'ChallengeParameters': {},
				'AuthenticationResult': {
					'AccessToken': token,
					'ExpiresIn': 3600,
					'TokenType': 'Bearer',
					'RefreshToken': token,
					'IdToken': token,
				},
			} );
			return;
		}

		// Get User
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.GetUser' ) {
			let User = storage.tokens[body.AccessToken];
			if ( ! User ) {
				send( res, 401 );
				return
			}

			send( res, 200, renameProp( 'Attributes', 'UserAttributes', User ) );
			return;
		}

		// Admin Set User Password
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminSetUserPassword' ) {
			const User = storage.users.get( body.Username );
			if ( ! User ) {
				send( res, 404 );
				return;
			}

			const key = `${body.Username}:${body.Password}`;
			storage.auth[key] = User;
			storage.links.get( User ).push( () => delete storage.auth[key] );

			send( res, 200, renameProp( 'Attributes', 'UserAttributes', User ) );
			return;
		}

		// Admin Get User.
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminGetUser' ) {
			send( res, 200, renameProp( 'Attributes', 'UserAttributes', storage.users.get( body.Username ) ) );
			return;
		}

		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminAddUserToGroup' ) {
			const User = storage.users.get( body.Username );
			if ( ! User ) {
				send( res, 404 );
				return;
			}

			const Groups = User.groups = User.groups || new Set();
			Groups.add( body.GroupName );
			send( res, 200 );
			return;
		}

		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityProviderService.AdminListGroupsForUser' ) {
			const User = storage.users.get( body.Username );
			if ( ! User ) {
				send( res, 404 );
				return;
			}

			const Groups = User.groups = User.groups || new Set();
			send( res, 200, {
				Groups: [ ...Groups ].map( GroupName => ( {
					GroupName,
					UserPoolId: body.UserPoolId,
					LastModifiedDate: 1548097827.125,
					CreationDate: 1548097827.125,
				} ) ),
			} );
			return;
		}

		if ( req.headers['x-amz-target'] === 'TrentService.Decrypt' ) {
			const { CiphertextBlob, KeyId = '349a3879-11a2-445d-95d0-0ba526ae0a1c' } = body
			if (CiphertextBlob === 'AQIDAHjfsMkryEoNjhnww46u7deWahqtig9q5lAzCNI77t8sDAHgysjgmApFvD1iyi4SzXtVAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMQ3ghIFmJdFE2hNp+AgEQgDsuPR8MN0gIbpBeI6pzagZvLg2Y7J6qrxaAb70mVM1qGSO7FmrIFnsMAYjg6M/7NeptSjGdjjGVtMqoug==') {
				send( res, 200, {
					KeyId: `arn:aws:kms:eu-west-1:123456789010:key/${KeyId}`,
					Plaintext: 'wu5MqCDkKzPfAQoZAfDuBbodlC7Brmwq/2hj48X76AI=',
					EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
				} );
				return
			}

                        if (CiphertextBlob === 'AQIDAHgUKAdXUQ893Kgcn5VWOTowFgXi5CbaL96g1wNgcEgkQgEQnxgmQLpWgJquZ6zDeeOMAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMhs6KB1RoxyND+XiXAgEQgDst07n+He+VKUkw8BJ5sOCutpYwsgz+Bqtd0usUdqXZppRVAW9kOR21nj/heeKnufJu1tNLhmpaSgL94g==') {
                                send( res, 200, {
                                        KeyId: `arn:aws:kms:eu-west-1:123456789010:key/${KeyId}`,
                                        Plaintext: 'AdwsxSZHDzFpu4ZUTY9LIo23NW9MRpN6RIyZhEaxB2c=',
                                        EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
                                } );
                                return
                        }

                        if (CiphertextBlob === 'AQIDAHgUKAdXUQ893Kgcn5VWOTowFgXi5CbaL96g1wNgcEgkQgGHhACaJFdMEJumJ0BmaK7ZAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMPy+1eF3v8QUZ5YlZAgEQgDuHVvFF+tNeLdwY/3roXfcO4IX+RPHS4eSkwNr6WD9JIcxqHcxuj8eoU2g2fNTXgCCNBO+wIlIGpZeuvg==') {
                                send( res, 200, {
                                        KeyId: `arn:aws:kms:eu-west-1:123456789010:key/${KeyId}`,
                                        Plaintext: 'V+jITuFQmSyZqAvwS1p77oe7kZxlMWM3om4/l0o+ADY=',
                                        EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
                                } );
                                return
                        }

                        const decipher = crypto.createDecipheriv(KMSAlg, KMSKey, iv);
			const decrypted = Buffer.concat([ decipher.update(Buffer.from(CiphertextBlob, 'base64')), decipher.final() ]);
			send( res, 200, {
				KeyId: `arn:aws:kms:eu-west-1:123456789010:key/${KeyId}`,
				Plaintext: decrypted.toString('base64'),
				EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
			} );
			return;
		}

		if ( req.headers['x-amz-target'] === 'TrentService.Encrypt' ) {
			const { Plaintext, KeyId = '349a3879-11a2-445d-95d0-0ba526ae0a1c' } = body
			const cipher = crypto.createCipheriv(KMSAlg, KMSKey, iv);
			const encrypted = Buffer.concat([ cipher.update(Buffer.from(Plaintext, 'base64')), cipher.final() ]);
			send( res, 200, {
				CiphertextBlob: encrypted.toString('base64'),
				KeyId: `arn:aws:kms:eu-west-1:123456789010:key/${KeyId}`,
				EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
			} );
			return;
		}

		if ( req.headers['x-amz-target'] === 'TrentService.GenerateDataKey' ) {
			const { KeyId = '349a3879-11a2-445d-95d0-0ba526ae0a1c', KeySpec = 'AES_256' } = body
			const random = crypto.randomBytes(32);
			const cipher = crypto.createCipheriv(KMSAlg, KMSKey, iv);
			const encrypted = Buffer.concat([ cipher.update(random), cipher.final() ]);
			send( res, 200, {
				CiphertextBlob: encrypted.toString('base64'),
				Plaintext: random.toString('base64'),
				KeyId: `arn:aws:kms:eu-west-1:123456789010:key/${KeyId}`,
			} );
			return;
		}

		console.error( req.headers['x-amz-target'] )
		process.exit( 123 )
		send( res, 500 );
	} ),
);
