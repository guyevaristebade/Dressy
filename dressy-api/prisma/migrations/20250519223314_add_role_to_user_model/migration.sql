/*
  Warnings:

  - The `gender` column on the `Profile` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- CreateEnum
CREATE TYPE "Gender" AS ENUM ('MALE', 'FEMALE', 'OTHER');

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'PREMIUM', 'STYLIST', 'MODERATOR', 'ADMIN');

-- AlterTable
ALTER TABLE "Profile" ALTER COLUMN "bio" SET DEFAULT '',
ALTER COLUMN "avatar" SET DEFAULT '',
DROP COLUMN "gender",
ADD COLUMN     "gender" "Gender";

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "role" "Role" NOT NULL DEFAULT 'USER';
