import { Test, TestingModule } from '@nestjs/testing';
import { FindingsService } from './findings.service';
import { PrismaService } from '../prisma/prisma.service';
import { NotFoundException } from '@nestjs/common';
import { FindingStatus } from './dto/update-finding.dto';
import { FindingSeverity, FindingCategory } from './dto/create-finding.dto';

describe('FindingsService', () => {
  let service: FindingsService;

  const mockPrismaService = {
    auditFinding: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
      count: jest.fn(),
    },
    audit: {
      findFirst: jest.fn(),
      update: jest.fn(),
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FindingsService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
      ],
    }).compile();

    service = module.get<FindingsService>(FindingsService);

    // Reset all mocks before each test
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    const mockCreateDto = {
      title: 'Access Control Gap',
      description: 'Insufficient access controls on production database',
      severity: FindingSeverity.HIGH,
      category: FindingCategory.CONTROL_DEFICIENCY,
      auditId: 'audit-123',
      organizationId: 'org-123',
    };

    const mockCreatedFinding = {
      id: 'finding-123',
      findingNumber: 'F-001',
      ...mockCreateDto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('should create a finding with auto-generated findingNumber', async () => {
      mockPrismaService.auditFinding.count.mockResolvedValue(0);
      mockPrismaService.auditFinding.create.mockResolvedValue(mockCreatedFinding);
      mockPrismaService.audit.findFirst.mockResolvedValue({
        id: 'audit-123',
        organizationId: 'org-123',
      });

      const result = await service.create(mockCreateDto, 'org-123', 'user-123');

      expect(mockPrismaService.auditFinding.count).toHaveBeenCalledWith({
        where: { auditId: 'audit-123' },
      });
      expect(mockPrismaService.auditFinding.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            title: 'Access Control Gap',
            severity: FindingSeverity.HIGH,
            findingNumber: 'F-001',
            identifiedBy: 'user-123',
          }),
        })
      );
      expect(result).toEqual(mockCreatedFinding);
    });

    it('should increment finding number based on existing count', async () => {
      mockPrismaService.auditFinding.count.mockResolvedValue(5);
      mockPrismaService.auditFinding.create.mockResolvedValue({
        ...mockCreatedFinding,
        findingNumber: 'F-006',
      });
      mockPrismaService.audit.findFirst.mockResolvedValue({
        id: 'audit-123',
        organizationId: 'org-123',
      });

      await service.create(mockCreateDto, 'org-123', 'user-123');

      expect(mockPrismaService.auditFinding.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            findingNumber: 'F-006',
          }),
        })
      );
    });
  });

  describe('findAll', () => {
    const mockFindings = [
      {
        id: 'finding-1',
        findingNumber: 'F-001',
        title: 'Finding 1',
        severity: 'high',
        status: 'open',
      },
      {
        id: 'finding-2',
        findingNumber: 'F-002',
        title: 'Finding 2',
        severity: 'medium',
        status: 'resolved',
      },
    ];

    it('should return all findings for an organization', async () => {
      mockPrismaService.auditFinding.findMany.mockResolvedValue(mockFindings);

      const result = await service.findAll('org-123');

      expect(mockPrismaService.auditFinding.findMany).toHaveBeenCalledWith({
        where: { organizationId: 'org-123' },
        include: expect.any(Object),
        orderBy: expect.any(Array),
      });
      expect(result).toEqual(mockFindings);
    });

    it('should filter by auditId', async () => {
      mockPrismaService.auditFinding.findMany.mockResolvedValue(mockFindings);

      await service.findAll('org-123', { auditId: 'audit-123' });

      expect(mockPrismaService.auditFinding.findMany).toHaveBeenCalledWith({
        where: { organizationId: 'org-123', auditId: 'audit-123' },
        include: expect.any(Object),
        orderBy: expect.any(Array),
      });
    });

    it('should filter by severity', async () => {
      mockPrismaService.auditFinding.findMany.mockResolvedValue([mockFindings[0]]);

      await service.findAll('org-123', { severity: 'high' });

      expect(mockPrismaService.auditFinding.findMany).toHaveBeenCalledWith({
        where: { organizationId: 'org-123', severity: 'high' },
        include: expect.any(Object),
        orderBy: expect.any(Array),
      });
    });

    it('should filter by status', async () => {
      mockPrismaService.auditFinding.findMany.mockResolvedValue([mockFindings[1]]);

      await service.findAll('org-123', { status: 'resolved' });

      expect(mockPrismaService.auditFinding.findMany).toHaveBeenCalledWith({
        where: { organizationId: 'org-123', status: 'resolved' },
        include: expect.any(Object),
        orderBy: expect.any(Array),
      });
    });
  });

  describe('findOne', () => {
    const mockFinding = {
      id: 'finding-123',
      findingId: 'FND-001',
      title: 'Test Finding',
      severity: 'high',
      remediationPlan: null,
      evidence: [],
      comments: [],
    };

    it('should return a single finding', async () => {
      mockPrismaService.auditFinding.findFirst.mockResolvedValue(mockFinding);

      const result = await service.findOne('finding-123', 'org-123');

      expect(mockPrismaService.auditFinding.findFirst).toHaveBeenCalledWith({
        where: { id: 'finding-123', organizationId: 'org-123' },
        include: expect.any(Object),
      });
      expect(result).toEqual(mockFinding);
    });

    it('should throw NotFoundException if finding not found', async () => {
      mockPrismaService.auditFinding.findFirst.mockResolvedValue(null);

      await expect(service.findOne('nonexistent', 'org-123')).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const mockUpdateDto = {
      title: 'Updated Finding Title',
      status: FindingStatus.REMEDIATION_IN_PROGRESS,
    };

    const mockUpdatedFinding = {
      id: 'finding-123',
      ...mockUpdateDto,
    };

    it('should update a finding', async () => {
      mockPrismaService.auditFinding.findFirst.mockResolvedValue({ id: 'finding-123' });
      mockPrismaService.auditFinding.update.mockResolvedValue(mockUpdatedFinding);

      const result = await service.update('finding-123', 'org-123', mockUpdateDto);

      expect(mockPrismaService.auditFinding.update).toHaveBeenCalledWith({
        where: { id: 'finding-123' },
        data: expect.objectContaining({
          title: 'Updated Finding Title',
          status: FindingStatus.REMEDIATION_IN_PROGRESS,
        }),
        include: expect.any(Object),
      });
      expect(result).toEqual(mockUpdatedFinding);
    });

    it('should throw NotFoundException if finding does not exist', async () => {
      mockPrismaService.auditFinding.findFirst.mockResolvedValue(null);

      await expect(service.update('nonexistent', 'org-123', mockUpdateDto)).rejects.toThrow(
        NotFoundException
      );
    });

    it('should set responseDate when managementResponse is provided', async () => {
      mockPrismaService.auditFinding.findFirst.mockResolvedValue({
        id: 'finding-123',
      });
      mockPrismaService.auditFinding.update.mockResolvedValue({
        id: 'finding-123',
        managementResponse: 'We will fix this',
        responseDate: new Date(),
      });

      await service.update('finding-123', 'org-123', { managementResponse: 'We will fix this' });

      expect(mockPrismaService.auditFinding.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            managementResponse: 'We will fix this',
            responseDate: expect.any(Date),
          }),
        })
      );
    });
  });
});
