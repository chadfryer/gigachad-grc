import { Test, TestingModule } from '@nestjs/testing';
import { VendorsService, parseFrequencyToMonths, formatFrequencyLabel } from './vendors.service';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';
import { TprmConfigService } from '../config/tprm-config.service';
import { CacheService } from '@gigachad-grc/shared';
import { NotFoundException } from '@nestjs/common';

describe('VendorsService', () => {
  let service: VendorsService;

  const mockPrismaService = {
    vendor: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      count: jest.fn(),
    },
    vendorContact: {
      create: jest.fn(),
      findMany: jest.fn(),
      deleteMany: jest.fn(),
    },
    vendorAssessment: {
      findMany: jest.fn(),
      count: jest.fn(),
    },
    vendorRisk: {
      findMany: jest.fn(),
    },
  };

  const mockAuditService = {
    log: jest.fn(),
  };

  const mockConfigService = {
    getTierReviewFrequency: jest.fn().mockResolvedValue('annual'),
  };

  const mockCacheService = {
    get: jest.fn(),
    set: jest.fn(),
    delete: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VendorsService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: AuditService, useValue: mockAuditService },
        { provide: TprmConfigService, useValue: mockConfigService },
        { provide: CacheService, useValue: mockCacheService },
      ],
    }).compile();

    service = module.get<VendorsService>(VendorsService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('parseFrequencyToMonths', () => {
    it('should parse predefined frequencies', () => {
      expect(parseFrequencyToMonths('monthly')).toBe(1);
      expect(parseFrequencyToMonths('quarterly')).toBe(3);
      expect(parseFrequencyToMonths('semi_annual')).toBe(6);
      expect(parseFrequencyToMonths('annual')).toBe(12);
      expect(parseFrequencyToMonths('biennial')).toBe(24);
    });

    it('should parse custom frequencies', () => {
      expect(parseFrequencyToMonths('custom_18')).toBe(18);
      expect(parseFrequencyToMonths('custom_6')).toBe(6);
    });

    it('should default to annual for invalid values', () => {
      expect(parseFrequencyToMonths('invalid')).toBe(12);
      expect(parseFrequencyToMonths('custom_abc')).toBe(12);
    });
  });

  describe('formatFrequencyLabel', () => {
    it('should format predefined frequencies', () => {
      expect(formatFrequencyLabel('quarterly')).toBe('Quarterly');
      expect(formatFrequencyLabel('annual')).toBe('Annual');
    });

    it('should format custom frequencies', () => {
      expect(formatFrequencyLabel('custom_18')).toBe('Every 18 months');
    });
  });

  describe('findAll', () => {
    const mockVendors = [
      {
        id: 'vendor-1',
        vendorId: 'VND-001',
        name: 'Test Vendor 1',
        status: 'active',
        tier: 'tier_1',
        _count: { assessments: 2, risks: 1 },
      },
      {
        id: 'vendor-2',
        vendorId: 'VND-002',
        name: 'Test Vendor 2',
        status: 'pending_onboarding',
        tier: 'tier_2',
        _count: { assessments: 0, risks: 0 },
      },
    ];

    it('should return paginated vendors', async () => {
      mockPrismaService.vendor.findMany.mockResolvedValue(mockVendors);
      mockPrismaService.vendor.count.mockResolvedValue(2);

      const result = await service.findAll('org-123', { page: 1, limit: 20 });

      expect(result.data).toHaveLength(2);
      expect(result.total).toBe(2);
      expect(result.page).toBe(1);
    });

    it('should filter by status', async () => {
      mockPrismaService.vendor.findMany.mockResolvedValue([mockVendors[0]]);
      mockPrismaService.vendor.count.mockResolvedValue(1);

      await service.findAll('org-123', { status: 'active' });

      expect(mockPrismaService.vendor.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: 'active',
          }),
        }),
      );
    });

    it('should filter by tier', async () => {
      mockPrismaService.vendor.findMany.mockResolvedValue([mockVendors[0]]);
      mockPrismaService.vendor.count.mockResolvedValue(1);

      await service.findAll('org-123', { tier: 'tier_1' });

      expect(mockPrismaService.vendor.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tier: 'tier_1',
          }),
        }),
      );
    });

    it('should search by name', async () => {
      mockPrismaService.vendor.findMany.mockResolvedValue([mockVendors[0]]);
      mockPrismaService.vendor.count.mockResolvedValue(1);

      await service.findAll('org-123', { search: 'Test' });

      expect(mockPrismaService.vendor.findMany).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    const mockVendor = {
      id: 'vendor-123',
      vendorId: 'VND-001',
      name: 'Test Vendor',
      status: 'active',
      contacts: [],
      assessments: [],
      risks: [],
    };

    it('should return a vendor by id', async () => {
      mockPrismaService.vendor.findFirst.mockResolvedValue(mockVendor);

      const result = await service.findOne('vendor-123', 'org-123');

      expect(mockPrismaService.vendor.findFirst).toHaveBeenCalledWith({
        where: { id: 'vendor-123', organizationId: 'org-123', deletedAt: null },
        include: expect.any(Object),
      });
      expect(result).toEqual(mockVendor);
    });

    it('should throw NotFoundException if vendor not found', async () => {
      mockPrismaService.vendor.findFirst.mockResolvedValue(null);

      await expect(service.findOne('nonexistent', 'org-123')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('create', () => {
    const mockCreateDto = {
      name: 'New Vendor',
      category: 'software_vendor',
      tier: 'tier_2',
      description: 'A test vendor',
    };

    const mockCreatedVendor = {
      id: 'vendor-123',
      vendorId: 'VND-001',
      ...mockCreateDto,
      status: 'pending_onboarding',
    };

    it('should create a vendor', async () => {
      mockPrismaService.vendor.count.mockResolvedValue(0);
      mockPrismaService.vendor.create.mockResolvedValue(mockCreatedVendor);

      const result = await service.create('org-123', mockCreateDto, 'user-123');

      expect(mockPrismaService.vendor.create).toHaveBeenCalled();
      expect(result).toEqual(mockCreatedVendor);
    });

    it('should generate vendorId based on count', async () => {
      mockPrismaService.vendor.count.mockResolvedValue(5);
      mockPrismaService.vendor.create.mockResolvedValue({
        ...mockCreatedVendor,
        vendorId: 'VND-006',
      });

      await service.create('org-123', mockCreateDto, 'user-123');

      expect(mockPrismaService.vendor.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            vendorId: 'VND-006',
          }),
        }),
      );
    });
  });

  describe('update', () => {
    const mockUpdateDto = {
      name: 'Updated Vendor',
      status: 'active',
    };

    it('should update a vendor', async () => {
      mockPrismaService.vendor.findFirst.mockResolvedValue({ id: 'vendor-123' });
      mockPrismaService.vendor.update.mockResolvedValue({
        id: 'vendor-123',
        ...mockUpdateDto,
      });

      const result = await service.update('vendor-123', 'org-123', mockUpdateDto, 'user-123');

      expect(mockPrismaService.vendor.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'vendor-123' },
        }),
      );
      expect(result.name).toBe('Updated Vendor');
    });

    it('should throw NotFoundException if vendor not found', async () => {
      mockPrismaService.vendor.findFirst.mockResolvedValue(null);

      await expect(
        service.update('nonexistent', 'org-123', mockUpdateDto, 'user-123'),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
