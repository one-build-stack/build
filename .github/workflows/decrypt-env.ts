/**
 * 环境变量解密工具
 * 用于解密在GitHub Actions工作流中传递的加密环境变量
 */
import CryptoJS from "crypto-js";
import { writeFileSync } from 'fs';
/**
 * 使用提供的密钥加密数据
 * @param data 需要加密的数据
 * @param key 加密密钥
 * @returns 加密后的数据（格式：iv:加密内容，均为base64编码）
 */
export function encrypt(data: string, key: string): string {
  // 确保密钥长度为32字节（256位）
  const paddedKey = key.padEnd(32, "0").slice(0, 32);

  // 创建随机初始化向量
  const iv = CryptoJS.lib.WordArray.random(16);

  // 创建密钥
  const keyWordArray = CryptoJS.enc.Utf8.parse(paddedKey);

  // 加密数据
  const encrypted = CryptoJS.AES.encrypt(data, keyWordArray, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  // 返回格式：iv:encrypted (都是base64编码)
  return `${CryptoJS.enc.Base64.stringify(iv)}:${encrypted.toString()}`;
}

/**
 * 使用提供的密钥解密数据
 * @param encryptedData 加密的数据（格式：iv:加密内容）
 * @param key 解密密钥
 * @returns 解密后的原始数据
 */
export function decrypt(encryptedData: string, key: string): string {
  // 分割iv和加密内容
  const [ivBase64, encryptedBase64] = encryptedData.split(":");

  if (!ivBase64 || !encryptedBase64) {
    throw new Error("加密数据格式无效");
  }

  // 确保密钥长度为32字节（256位）
  const paddedKey = key.padEnd(32, "0").slice(0, 32);

  // 从base64还原iv
  const iv = CryptoJS.enc.Base64.parse(ivBase64);

  // 创建密钥
  const keyWordArray = CryptoJS.enc.Utf8.parse(paddedKey);

  // 解密数据
  const decrypted = CryptoJS.AES.decrypt(encryptedBase64, keyWordArray, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  return decrypted.toString(CryptoJS.enc.Utf8);
}

/**
 * 主函数
 */
function main() {
  // 获取命令行参数
  const args = process.argv.slice(2);
  const encryptedData = args[0];
  const key = args[1];
  const outputFile = args[2];

  if (!encryptedData || !key || !outputFile) {
    console.error('错误:缺少必需参数 (加密数据, 密钥, 输出文件路径)');
    process.exit(1);
  }

  try {
    // 解密数据
    const decrypted = decrypt(encryptedData, key);
    if (!decrypted) {
      throw new Error('解密结果为空');
    }

    let output: string;

    // 尝试解析为JSON
    try {
      const envVars = JSON.parse(decrypted);

      // 如果是对象,转换为环境变量格式
      if (typeof envVars === 'object' && envVars !== null && !Array.isArray(envVars)) {
        output = Object.entries(envVars).map(([key, value]) => {
          return `${key}=${value}`;
        }).join('\n');
      } else {
        // 如果不是对象,直接输出原始字符串
        output = decrypted;
      }
    } catch {
      // 如果不是JSON,直接输出原始解密字符串
      output = decrypted;
    }

    // 写入到输出文件(安全考虑:不输出到标准输出)
    writeFileSync(outputFile, output);

  } catch (error) {
    console.error('处理环境变量失败:', error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

// 执行主函数
main();
