import { UserStatus } from '@prisma/client';
import { jwtHelpers } from '../../../helpers/jwtHelpers';
import prisma from '../../../shared/prisma';
import * as bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';

const loginUser = async (payload: { email: string; password: string }) => {
	const userData = await prisma.user.findUniqueOrThrow({
		where: {
			email: payload.email,
			status: UserStatus.ACTIVE,
		},
	});

	// check password correct
	const isCorrectPassword: boolean = await bcrypt.compare(payload.password, userData.password);

	if (!isCorrectPassword) {
		throw new Error('Password incorrect!');
	}

	// generate access token
	const accessToken = jwtHelpers.generateToken(
		{
			email: userData.email,
			role: userData.role,
		},
		'abcdefg',
		'5m'
	);

	// generate refresh token
	const refreshToken = jwtHelpers.generateToken(
		{
			email: userData.email,
			role: userData.role,
		},
		'abcdefghgijklmnop',
		'30d'
	);

	return {
		accessToken,
		refreshToken,
		needPasswordChange: userData.needPasswordChange,
	};
};

const refreshToken = async (token: string) => {
	// verify token
	let decodedData;
	try {
		decodedData = jwtHelpers.verifyToken(token, 'abcdefghgijklmnop');
	} catch (err) {
		throw new Error('You are not authorized!');
	}

	// check user exists
	const userData = await prisma.user.findUniqueOrThrow({
		where: {
			email: decodedData.email,
			status: UserStatus.ACTIVE,
		},
	});

	// generate access token new
	const accessToken = jwtHelpers.generateToken(
		{
			email: userData.email,
			role: userData.role,
		},
		'abcdefg',
		'5m'
	);

	return {
		accessToken,
		needPasswordChange: userData.needPasswordChange,
	};
};

export const AuthServices = {
	loginUser,
	refreshToken,
};
