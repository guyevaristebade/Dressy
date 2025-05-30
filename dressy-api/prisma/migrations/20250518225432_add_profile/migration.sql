-- CreateTable
CREATE TABLE "Profile" (
    "id" TEXT NOT NULL,
    "fullName" TEXT,
    "profileName" TEXT,
    "bio" TEXT,
    "avatar" TEXT,
    "gender" TEXT,
    "totalSpending" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "totalOutfitCount" INTEGER NOT NULL DEFAULT 0,
    "totalOutfitLikes" INTEGER NOT NULL DEFAULT 0,
    "totalClothingCount" INTEGER NOT NULL DEFAULT 0,
    "totalClothingLikes" INTEGER NOT NULL DEFAULT 0,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Profile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Profile_userId_key" ON "Profile"("userId");

-- AddForeignKey
ALTER TABLE "Profile" ADD CONSTRAINT "Profile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
