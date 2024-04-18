require("dotenv").config();
import jwt from "jsonwebtoken";
import { UserRepository } from "../user/domain/userRepository/UserRepository";
import { Request, Response } from "express";
import { NextFunction } from "express";

export function verifyToken (req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader;
    if (!token) {
      return res.sendStatus(401);
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string);

      console.log("decoded", decoded);
      (req as any).user_id = decoded;

      next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
