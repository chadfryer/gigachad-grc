import { PrismaService } from './prisma/prisma.service';

const service = new PrismaService();
const _test = service.auditLog;
export {};
