import { Injectable } from '@nestjs/common';
import { PrismaService } from '../common/prisma.service';
import { QuestionStatus } from '@prisma/client';

export interface SimilarQuestion {
  id: string;
  questionText: string;
  answerText: string | null;
  status: string;
  category: string | null;
  questionnaire: {
    id: string;
    title: string;
    requesterName: string;
    company: string | null;
    completedAt: Date | null;
  };
  similarityScore: number;
}

@Injectable()
export class SimilarQuestionsService {
  constructor(private prisma: PrismaService) {}

  // Find similar questions to the given question text
  async findSimilarQuestions(
    organizationId: string,
    questionText: string,
    excludeQuestionId?: string,
    limit = 10
  ): Promise<SimilarQuestion[]> {
    // Normalize and tokenize the question
    const tokens = this.tokenize(questionText);

    if (tokens.length === 0) {
      return [];
    }

    // Get all completed questions from the organization
    const questions = await this.prisma.questionnaireQuestion.findMany({
      where: {
        questionnaire: {
          organizationId,
          deletedAt: null,
        },
        status: QuestionStatus.completed,
        answerText: { not: null },
        ...(excludeQuestionId ? { id: { not: excludeQuestionId } } : {}),
      },
      include: {
        questionnaire: {
          select: {
            id: true,
            title: true,
            requesterName: true,
            company: true,
            completedAt: true,
          },
        },
      },
      take: 500, // Limit for performance
    });

    // Score each question based on similarity
    const scored = questions.map((q) => {
      const candidateTokens = this.tokenize(q.questionText);
      const score = this.calculateSimilarity(tokens, candidateTokens);
      return {
        id: q.id,
        questionText: q.questionText,
        answerText: q.answerText,
        status: q.status,
        category: q.category,
        questionnaire: q.questionnaire,
        similarityScore: score,
      };
    });

    // Filter and sort by similarity
    return scored
      .filter((q) => q.similarityScore > 20) // Minimum threshold
      .sort((a, b) => b.similarityScore - a.similarityScore)
      .slice(0, limit);
  }

  // Find duplicate questions within a questionnaire
  async findDuplicatesInQuestionnaire(
    questionnaireId: string,
    organizationId: string
  ): Promise<
    { questionId: string; duplicates: { id: string; questionText: string; similarity: number }[] }[]
  > {
    // SECURITY: Include organizationId in query to prevent IDOR
    // This ensures users can only find duplicates within questionnaires in their organization
    const questions = await this.prisma.questionnaireQuestion.findMany({
      where: {
        questionnaireId,
        questionnaire: {
          organizationId, // Tenant isolation - prevents cross-organization access
        },
      },
      select: {
        id: true,
        questionText: true,
      },
    });

    const duplicates: {
      questionId: string;
      duplicates: { id: string; questionText: string; similarity: number }[];
    }[] = [];

    for (let i = 0; i < questions.length; i++) {
      const currentTokens = this.tokenize(questions[i].questionText);
      const similarQuestions: { id: string; questionText: string; similarity: number }[] = [];

      for (let j = 0; j < questions.length; j++) {
        if (i === j) continue;

        const candidateTokens = this.tokenize(questions[j].questionText);
        const similarity = this.calculateSimilarity(currentTokens, candidateTokens);

        if (similarity >= 70) {
          similarQuestions.push({
            id: questions[j].id,
            questionText: questions[j].questionText,
            similarity,
          });
        }
      }

      if (similarQuestions.length > 0) {
        duplicates.push({
          questionId: questions[i].id,
          duplicates: similarQuestions.sort((a, b) => b.similarity - a.similarity),
        });
      }
    }

    return duplicates;
  }

  // Get answer suggestions based on similar questions
  async getAnswerSuggestions(
    organizationId: string,
    questionText: string,
    limit = 5
  ): Promise<{ question: string; answer: string; source: string; similarity: number }[]> {
    const similar = await this.findSimilarQuestions(organizationId, questionText, undefined, limit);

    return similar
      .filter((q) => q.answerText)
      .map((q) => ({
        question: q.questionText,
        answer: q.answerText!,
        source: `${q.questionnaire.title} - ${q.questionnaire.company || q.questionnaire.requesterName}`,
        similarity: q.similarityScore,
      }));
  }

  // Tokenize and normalize text for comparison
  private tokenize(text: string): string[] {
    // Common stop words to ignore
    const stopWords = new Set([
      'a',
      'an',
      'the',
      'is',
      'are',
      'was',
      'were',
      'be',
      'been',
      'being',
      'have',
      'has',
      'had',
      'do',
      'does',
      'did',
      'will',
      'would',
      'could',
      'should',
      'may',
      'might',
      'must',
      'can',
      'to',
      'of',
      'in',
      'for',
      'on',
      'with',
      'at',
      'by',
      'from',
      'or',
      'and',
      'that',
      'this',
      'it',
      'its',
      'as',
      'if',
      'your',
      'you',
      'we',
      'our',
      'their',
      'what',
      'which',
      'who',
      'how',
      'when',
      'where',
      'why',
      'does',
      'please',
      'describe',
      'explain',
      'provide',
      'regarding',
    ]);

    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter((word) => word.length > 2 && !stopWords.has(word));
  }

  // Calculate Jaccard similarity between two token sets
  private calculateSimilarity(tokens1: string[], tokens2: string[]): number {
    if (tokens1.length === 0 || tokens2.length === 0) {
      return 0;
    }

    const set1 = new Set(tokens1);
    const set2 = new Set(tokens2);

    let intersection = 0;
    set1.forEach((token) => {
      if (set2.has(token)) {
        intersection++;
      }
    });

    const union = set1.size + set2.size - intersection;

    if (union === 0) return 0;

    // Calculate Jaccard similarity and scale to 0-100
    const jaccard = (intersection / union) * 100;

    // Boost score if many tokens match (longer overlap is more significant)
    const overlapBonus = Math.min(intersection * 3, 20);

    return Math.min(Math.round(jaccard + overlapBonus), 100);
  }
}
