const { inspect } = require( 'util' );
const { send, json } = require( 'micro' );
const {
	router,
	options,
	post,
	get,
} = require( 'micro-fork' );

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

		send( res, 500 );
	} ),
);
